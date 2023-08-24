import Ajv from 'ajv';
import Ajv2019 from 'ajv/dist/2019.js';
import Ajv2020 from 'ajv/dist/2020.js';
import AjvDraft07 from 'ajv';
import addFormats from 'ajv-formats';
import axios from 'axios';
import moment from "moment";
import { importJWK, JWK, jwtVerify } from 'jose';
import { defaultVerifyOptions, DetailedVerifyResults, VerifyOptions } from "../types/issue.types";
import { LegalEntityResolver } from './ResolverInterfaces/LegalEntityResolver';
import PublicKeyResolverBuilder from './PublicKeyResolverBuilder';
import { didKeyPublicKeyAdapter } from './Adapters/DidKeyPublicKeyAdapter';
import { didEbsiPublicKeyAdapter } from './Adapters/DidEbsiPublicKeyAdapter';
import base64url from "base64url";
import { JsonWebKey2020, Secp256k1KeyPair } from "@transmute/secp256k1-key-pair";
import { JWS } from '@transmute/jose-ld';
import * as secp256k1 from '@transmute/did-key-secp256k1';
import { PublicNodeWithPublicKeyJwk } from '@transmute/ld-key-pair';

/** Verifiable Credential Class */
export abstract class VC {
	verifyOptions: VerifyOptions = defaultVerifyOptions;


	constructor(
		protected legalEntityResolvers: LegalEntityResolver[] = []
	) { }


	public addLegalEntityResolver(legalEntityResolver: LegalEntityResolver): this {
		this.legalEntityResolvers.push(legalEntityResolver);
		return this;
	}

	public abstract verify(options?: VerifyOptions): Promise<{ result: boolean, msg: string }>;

	/**
	 * Helper function to select the correct constructor according to the VC format that is inserted.
	 * @param credential Credential Payload
	 * @returns - A new JwtVC or LdpVC Object
	 * @throws 'INVALID_CREDENTIAL_TYPE' error if credential provided is neither a string nor an object
	 * @example Build a JWT VC.
	 * ```ts
	 * const credential = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.eH9qoMvdv...'
	 * vcBuilder(credential)
	 * ```
	 */
	public static vcBuilder(credential: any): VC {
		try {
			if (JSON.parse(base64url.decode(credential.split('.')[0])).typ === 'JWT') {
				return new JwtVC(credential);
			}
			else {
				throw new Error('INVALID_CREDENTIAL_TYPE')
			}
		}
		catch(e) {
			return new LdpVC(JSON.parse(credential));
		}
	}
}


/**
 * Verifiable Credential using JWT (JSON Web Token)
 */
export class JwtVC extends VC {
	public jwtHeaderJson: {
		alg?: string;
		kid?: string;
		jwk?: JWK;
		typ?: string;
	};

	public jwtPayloadJson: {
		iat?: number;
		iss?: string;
		sub?: string;
		exp?: number;
		nbf?: number;
		jti?: string;
		aud?: string;
		vc: any;
	};

	public jwtProof: string;

	constructor(public credential: string) {
		super();
		this.jwtHeaderJson = JSON.parse(base64url.decode(credential.split('.')[0]));
		this.jwtPayloadJson = JSON.parse(base64url.decode(credential.split('.')[1]));
		this.jwtProof = credential.split('.')[2];
	}

	/**
	 * Get Credential Issuer
	 * @returns "iss" (Issuer) Claim value from Credential Payload
	 */
	public getIssuer(): string {
		return this.jwtPayloadJson.iss as string;
	}

	/**
	 * Get Audience
	 * @returns "aud" (Audience) Claim value from Credential Payload
	 */
	public getAudience(): string | undefined {
		return this.jwtPayloadJson.aud;
	}

	/**
	 * Get Unique Identifier
	 * @returns "jti" (Identifier) Claim value from Credential Payload
	 */
	public getIdentifier(): string | undefined {
		return this.jwtPayloadJson.jti;
	}

	/**
	 * Get Subject
	 * @returns "sub" (Subject) Claim value from Credential Payload
	 */
	public getSubject(): string | undefined {
		return this.jwtPayloadJson.sub;
	}

	/**
	 * Get Issuance Date
	 * @returns "iat" (Issued At) Claim value from Credential Payload
	 */
	public getIssDate(): number | undefined {
		return this.jwtPayloadJson.iat;
	}

	/**
	 * Validate Verifiable Credential
	 * @param audience - Audience string
	 * @param options - Options to disable selected verification checks or provide different APIs
	 */
	public async verify(options?: VerifyOptions): Promise<{ result: boolean, msg: string, validations: DetailedVerifyResults }> {

		if (options != undefined)
			this.verifyOptions = options;

		let errorMsgs: string[] = [];
		let result = true;
		let validations: DetailedVerifyResults = {
			constraintValidation: undefined,
			signatureValidation: undefined,
			attributeMappingValidation: undefined,
			schemaValidation: undefined
		}
		try {

			if(this.verifyOptions.constraintValidation === true) {
				try {
					await this.vcJwtConstraintValidation();
					validations.constraintValidation = true;
				}
				catch (err) {
					result = false;
					errorMsgs.push(err as string);
					validations.constraintValidation = false;
				}
			}

			if (this.verifyOptions.signatureValidation === true) {
				try {
					await this.vcJwtSignatureValidation();
					validations.signatureValidation = true;
				}
				catch (err) {
					result = false;
					errorMsgs.push(err as string);
					validations.signatureValidation = false;
				}
			}

			if (this.verifyOptions.attributeMappingValidation === true) {
				try {
					await this.vcJwtAttributeMappingValidation();
					validations.attributeMappingValidation = true;
				}
				catch (err) {
					result = false;
					errorMsgs.push(err as string);
					validations.attributeMappingValidation = false;
				}
			}

			if (this.verifyOptions.schemaValidation === true) {
				try {
					await this.vcJwtSchemaValidation();
					validations.schemaValidation = true;
				}
				catch (err) {
					result = false;
					errorMsgs.push(err as string);
					validations.schemaValidation = false;
				}
			}
		}
		catch (err) {
			console.error(err as string);
			result = false;
		}

		const msg: string = errorMsgs.join();

		// console.log(`Verifiable Credential Validation Complete: ${ result ? 'SUCCESS' : 'FAILURE'}`);
		return {result, msg, validations};
	}

	/**
	 * Validate JWT Constraints
	 * @returns void
	 * @throws 'EXPIRED' error if VC expiration date has passed
	 * @throws 'INVALID_NBF' error if current date is before NBF (not before) date
	 */
	private async vcJwtConstraintValidation() {
		const curDate = Date.now();

		// Check if vc has expired
		if(this.jwtPayloadJson.exp) {
			const expirationDate = this.jwtPayloadJson.exp * 1000;
			if( curDate >= expirationDate) {
				console.error('Verifiable Credential has expired');
				throw new Error('EXPIRED');
			}
		}
		
		// Check if it is too early to use vc
		if(this.jwtPayloadJson.nbf) {
			const validFromDate = this.jwtPayloadJson.nbf * 1000;
			if( curDate <= validFromDate) {
				console.error('Verifiable Credential cannot be accessed before nbf date');
				throw new Error('INVALID_NBF');
			}
		}

		// // Check audience
		// const vcAud = this.jwtPayloadJson.aud;
		// if(vcAud != undefined && audience !== vcAud ) {
		// 	console.error('Verifiable Credential audience does not match jwt aud');
		// 	throw new Error('INVALID_AUD');
		// }

		// console.log('VC JWT Constraint Validation: OK');
	}

	private async vcJwtSignatureValidation() {

		// Check 1: Check Trusted Issuers Registry
		let existsInTIR: boolean = false;
		try {
			let resolverResults = await Promise.all(this.legalEntityResolvers.map(resolver => resolver.isLegalEntity(this.getIssuer())));
			if (resolverResults.length == 0) {
				throw new Error("ISSUER_NOT_TRUSTED")
			}
			existsInTIR = resolverResults[0];
			if (!existsInTIR)
				throw new Error("ISSUER_NOT_TRUSTED")
		}
		catch(e) {
			existsInTIR = false
			throw new Error('ISSUER_NOT_TRUSTED');
		}


		// Step 2: Check DID Registry
		// EBSI_JWT_VC_004  JWT signature MUST be valid
		let publicKeyJwk: JWK | null;
		const resolverBuilder = new PublicKeyResolverBuilder()
			.addPublicKeyResolver(didKeyPublicKeyAdapter)
			.addPublicKeyResolver(didEbsiPublicKeyAdapter);
		try {
			const verificationMethod = this.jwtHeaderJson.kid as string;

			publicKeyJwk = await resolverBuilder.resolve(verificationMethod);

			if (!publicKeyJwk) {
				throw new Error("Couldn't resolve the public key for the issuer");
			}
			console.log('Resolved Public Key:', publicKeyJwk);
		} catch (e) {
			console.error('Error resolving public key:', e);
			throw new Error("Couldn't resolve the public key for the issuer");
		}

		let ecPublicKey;
		try {
			ecPublicKey = await importJWK(publicKeyJwk, this.jwtHeaderJson.alg);
		}
		catch(e) {
			throw "Error while importing public key of issuer: " + e;
		}


		try {
			await jwtVerify(this.credential, ecPublicKey);
		}
		catch(e) {
			throw new Error('JWT_VERIFY_ERR');
		}

		// console.log('VC JWT SIGNATURE Validation: OK');
	}
	
	private async vcJwtAttributeMappingValidation(): Promise<boolean> {

		// ref: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/Verifiable+Credential+and+Verifiable+Presentation+validation+process
		// EBSI_JWT_VC_001  JWT Claim -> vc Property match
		// iat → issued
		if (this.jwtPayloadJson.iat !== moment(this.jwtPayloadJson.vc.issued).unix()) {
			console.error('JWT iat and vc issued do not match');
			throw new Error('IAT_ISSUED_MISMATCH');
		}

		// nbf → validFrom/issuanceDate
		if(this.jwtPayloadJson.nbf != moment(this.jwtPayloadJson.vc.validFrom).unix()){
			console.error('JWT nbf and vc validFrom do not match');
			throw new Error('NBF_VALIDFROM_MISMATCH');
		}
		if(this.jwtPayloadJson.nbf != moment(this.jwtPayloadJson.vc.issuanceDate).unix()){
			console.error('JWT nbf and vc issuanceDate do not match');
			throw new Error('NBF_ISSUANCEDATE_MISMATCH');
		}

		// exp → expirationDate
		if(this.jwtPayloadJson.exp !== moment(this.jwtPayloadJson.vc.expirationDate).unix()){
			if(this.jwtPayloadJson.exp !== undefined || this.jwtPayloadJson.vc.expirationDate !== undefined ){
				console.error('JWT exp and vc expirationDate do not match');
				throw new Error('EXP_EXPIRATIONDATE_MISMATCH');
			}
		}

		// jti → id
		if(this.jwtPayloadJson.jti !== this.jwtPayloadJson.vc.id){
			console.error('JWT jti and vc id do not match');
			throw new Error('JTI_ID_MISMATCH');
		}

		// iss → issuer
		if(this.jwtPayloadJson.iss != this.jwtPayloadJson.vc.issuer){
			console.error('JWT iss and vc issuer do not match');
			throw new Error('ISS_ISSUER_MISMATCH');
		}

		// sub → credentialSubject.id
		if(this.jwtPayloadJson.sub != this.jwtPayloadJson.vc.credentialSubject.id){
			console.error('JWT sub and vc credentialSubject.id do not match');
			throw new Error('SUB_CREDENTIALSUBJECTID_MISMATCH');
		}


		// EBSI_JWT_VC_002  JWT header kid related to the issuer
		if(this.jwtHeaderJson.kid) {
			const pureIssuer = this.jwtHeaderJson.kid.split('#')[0];
			if(!(pureIssuer === this.jwtPayloadJson.vc.issuer)) {
				console.error('JWT kid does not come from vc issuer');
				throw new Error('KID_ISSUER_MISMATCH');
			}
		}

		return true;
	}


	private async vcJwtSchemaValidation() {

		const axiosTimeout: number = 5000;

		// Get current schema
		const schemaUri = this.jwtPayloadJson.vc.credentialSchema.id;

		const schemaStr = await axios.get(schemaUri,
			{timeout: axiosTimeout})
			.catch(() => {throw new Error('SCHEMA_TIMEOUT')});
		const schema = schemaStr.data;

		var ajv: Ajv;
		switch (schema.$schema) {
			case "https://json-schema.org/draft/2020-12/schema": {
				ajv = new Ajv2020({ allErrors: true });
				break;
			}
			case "https://json-schema.org/draft/2019-09/schema": {
				ajv = new Ajv2019({ allErrors: true });
				break;
			}
			case "http://json-schema.org/draft-07/schema#": {
				ajv = new AjvDraft07({ allErrors: true });
				break;
			}
			default: {
				console.error(`Unknown version "${schema.$schema}"`);
				throw new Error('UNKNOWN_SCHEMA_VERSION');
			}
		}
		addFormats(ajv);
		ajv.addSchema(schema, schemaUri);

		// Get external schemas, if any, starting with current schema
		var curSchema = schema;
		while(curSchema !== undefined && curSchema.allOf !== undefined) {
			for (let i = 0; i < curSchema.allOf.length; i++) {
				const element = curSchema.allOf[i];
				if (element.$ref) {
					const extSchemaUri = element.$ref;
					const extSchemaStr = await axios.get(extSchemaUri,
						{timeout: axiosTimeout})
						.catch(() => {throw new Error('EXT_SCHEMA_TIMEOUT')});
					const extSchema = extSchemaStr.data;
					ajv.addSchema(extSchema,element.$ref);
					curSchema = extSchema;
					break;	// recursively get external schemas of the external schema
				}
			}
		}

		const validate = ajv.compile(schema);
		const valid = validate(this.jwtPayloadJson.vc);
		if(!valid){
			let errorArray: string[] = [];
			if(validate.errors) {
				validate.errors.forEach(error => {
					if(error.message){
						errorArray.push(error.message);
					}
				});
			}
			const errorStr: string = errorArray.toString();

			console.error('VC failed to pass JSON Schema validation. Errors: \n'+errorStr);
			throw new Error('VC_SCHEMA_VALIDATION_FAIL');
		}
		return true;
	}
}

/**
 * Verifiable Credential using JSON-LD
 */
export class LdpVC extends VC {
	public vc: any;
	constructor(public credential: any) {
		super();
		console.log("cred: ", credential);
		this.vc = credential;
	}

	/**
	 * Validate Verifiable Credential
	 * @param audience - Audience string
	 * @param options - Options to disable selected verification checks or provide different APIs
	 */
	public async verify(options?: VerifyOptions): Promise<{ result: boolean, msg: string, validations: DetailedVerifyResults }> {
		if (options != undefined) {
			this.verifyOptions = options;
		}
		const { didDocument } = await secp256k1.resolve(
			this.vc.proof.verificationMethod,
			{ accept: 'application/did+json' }
		);

		const publicKey = (didDocument.verificationMethod[0] as PublicNodeWithPublicKeyJwk).publicKeyJwk;
		const controller = didDocument.verificationMethod[0].controller;
		let errorMsgs: string[] = [];
		let result = true;
		let validations: DetailedVerifyResults = {
			constraintValidation: undefined,
			signatureValidation: undefined,
			attributeMappingValidation: undefined,
			schemaValidation: undefined
		}
		const signatureValue = this.vc.proof.proofValue;

		// Prepare the data for verification (exclude the 'proof' section)
		const dataToVerify = this.vc;
		delete dataToVerify.proof;
		const jsonwebkey2020: JsonWebKey2020 = {
			id: "1",
			type: 'JsonWebKey2020',
			controller: controller,
			privateKeyJwk: null,
			publicKeyJwk: publicKey
		}
		const k = await Secp256k1KeyPair.from(jsonwebkey2020);
		const verifier = JWS.createVerifier(k.verifier(), 'ES256K', {
			detached: false,
		});
		result = await verifier.verify({
			data: dataToVerify,
			signature: signatureValue,
		});

		const msg: string = errorMsgs.join();

		console.log(`Verifiable Credential Validation Complete: ${ result ? 'SUCCESS' : 'FAILURE'}`);
		return { result, msg, validations };
	}

}
import Ajv from "ajv";
import Ajv2019 from "ajv/dist/2019";
import Ajv2020 from "ajv/dist/2020";
import AjvDraft07 from 'ajv';
import addFormats from 'ajv-formats';
import axios from "axios";
import moment from "moment";
import { base64url, importJWK, jwtVerify } from "jose";
import { defaultVerifyOptions, DetailedVerifyResults, VerifyOptions } from "../types/issue.types";
import { VC } from "./vc";
import { LegalEntityResolver } from "./ResolverInterfaces/LegalEntityResolver";
import { PublicKeyResolver } from "./ResolverInterfaces/PublicKeyResolver";

export abstract class VP {
	verifyOptions: VerifyOptions = defaultVerifyOptions;

	constructor(protected publicKeyResolvers: PublicKeyResolver[] = [],
		protected legalEntityResolvers: LegalEntityResolver[] = []) { }

	public addPublicKeyResolver(publicKeyResolver: PublicKeyResolver): this {
		this.publicKeyResolvers.push(publicKeyResolver);
		return this;
	}
		
	public addLegalEntityResolver(legalEntityResolver: LegalEntityResolver): this {
		this.legalEntityResolvers.push(legalEntityResolver);
		return this;
	}

	public abstract verify(audience: string | string[], options?: VerifyOptions): Promise<{ result: boolean }>;
	
}

export class JwtVP extends VP {
	public jwtHeaderJson: {
		alg?: string;
		kid?: string;
		typ?: string;
	};

	public jwtPayloadJson: {
		iat?: number;
		iss?: string;
		sub?: string;
		exp?: number;
		nbf?: number;
		jti?: string;
		aud?: string | string[];
		vp: {
			verifiableCredential: any[]; // contains a list of VCs (can be of any format jwt_vc, ldp_vp)
			[x: string]: any;
		}
	};

	public jwtProof: string;

	/**
	 * 
	 * @param presentation - The VP in JWT format
	 */
	constructor(private presentation: string) {
		super();

		this.jwtHeaderJson = JSON.parse(new TextDecoder().decode(base64url.decode(presentation.split('.')[0])));
		this.jwtPayloadJson = JSON.parse(new TextDecoder().decode(base64url.decode(presentation.split('.')[1])));
		this.jwtProof = presentation.split('.')[2];
	}

	// getters
	public getIssuer(): string | undefined {
		return this.jwtPayloadJson.iss;
	}

	public getAudience(): string | string[] | undefined {
		return this.jwtPayloadJson.aud;
	}

	public getIdentifier(): string | undefined {
		return this.jwtPayloadJson.jti;
	}

	public getSubject(): string | undefined {
		return this.jwtPayloadJson.sub;
	}

	public getIssDate(): number | undefined {
		return this.jwtPayloadJson.iat;
	}

	/**
	 * 
	 * @param audience - Expected audience in uri format (can be DID or URL)
	 * @param publicKeyJwk - Public key of the VP issuer in JWK format
	 * @param options - Change the options to suppress checks in developer mode
	 * @returns 
	 */
	public async verify(audience: string | string[], options?: VerifyOptions): Promise<{ result: boolean, msg: string, validations: DetailedVerifyResults }> {

		if (options != undefined)
			this.verifyOptions = options;

		var result = true;
		var validations: DetailedVerifyResults = {
			constraintValidation: undefined,
			signatureValidation: undefined,
			attributeMappingValidation: undefined,
			schemaValidation: undefined
		}
		var errorMsgs: string[] = [];

		try {

			if (this.verifyOptions.constraintValidation === true) {
				try {
					await this.vpJwtConstraintValidation(audience);
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
					await this.vpJwtSignatureValidation();
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
					await this.vpJwtAttributeMappingValidation();
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
					await this.vpJwtSchemaValidation();
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
			console.error(err);
			result = false;
		}

		const msg: string = errorMsgs.join();

		return {result, msg, validations};

	}

	/**
	 * Validate expiration date, not before date, and audience
	 * @returns 'OK' on success or an error string on failure
	 */
	private async vpJwtConstraintValidation(audience: string | string[]) {

		const curDate = Date.now();

		// Check if vp has expired
		if(this.jwtPayloadJson.exp) {
			const expirationDate = this.jwtPayloadJson.exp * 1000;
			if( curDate >= expirationDate){
				console.error('Verifiable Presentation has expired');
				throw new Error('EXPIRED');
			}
		}
		
		// Check if it is too early to use vp
		if(this.jwtPayloadJson.nbf) {
			const validFromDate = this.jwtPayloadJson.nbf * 1000;
			if( curDate <= validFromDate) {
				console.error('Verifiable Presentation cannot be accessed before nbf date');
				throw new Error('INVALID_NBF');
			}
		}

		// Check audience
		const vpAud = this.jwtPayloadJson.aud;
		if( Array.isArray(audience) && Array.isArray(vpAud) ) {
			// both variables are arrays
			if(audience.sort().join() !== vpAud.sort().join()) {
				console.error('Verifiable Presentation audience does not match jwt aud');
				throw new Error('INVALID_AUD');
			}
		}
		else if( Array.isArray(audience) || Array.isArray(vpAud) ) {
			// one is a string and one is not
			console.error('Verifiable Presentation audience does not match jwt aud');
			throw new Error('INVALID_AUD');
		}
		else {
			// both are strings
			if( audience !== vpAud ) {
				console.error('Verifiable Presentation audience does not match jwt aud');
				throw new Error('INVALID_AUD');
			}
		}

	}

	private async vpJwtSignatureValidation() {


		let publicKeyJwk;
		try {
			let resolverResults = await Promise.all(this.publicKeyResolvers.map(resolver => resolver.getPublicKeyJwk(this.jwtHeaderJson.kid as string)));
			if (resolverResults.length == 0) {
				throw "Couldn't resolve the public key for the issuer";
			}
			publicKeyJwk = resolverResults[0];
		}
		catch(e) {
			throw "Couldn't resolve the public key for the issuer" + e;
		}

		// Step 1. Import Holder's public key
		let holderPublicKey;
		try {
			holderPublicKey = await importJWK(publicKeyJwk, this.jwtHeaderJson.alg);
		}
		catch(e) {
			console.error('Error importing VP holder public key');
			throw new Error('PUB_IMPORT_FAIL');
		}

		// Step 2. Verify signature using the Holder's public key
		try {
			await jwtVerify(this.presentation, holderPublicKey);
		}
		catch(e) {
			console.error('Error verifying VP signature');
			throw new Error('INVALID_SIGNATURE');
		}

		// Step 3. Validate each contained VC on the presentation
		const credentialList = this.jwtPayloadJson.vp.verifiableCredential;
		for (const vc of credentialList) {
			const genericVC = VC.vcBuilder(vc);
			const { result } = await genericVC.verify(this.verifyOptions);
			if (!result) { // is invalid
				console.error('At least one invalid VC is contained in the Presentation');
				throw new Error('INVALID_VC');
			}
		}

		// console.log('VP JWT Signature Validation: OK');
	}
	
	private async vpJwtAttributeMappingValidation() {

		// ref: https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/Verifiable+Credential+and+Verifiable+Presentation+validation+process

		// EBSI_JWT_VP_001  JWT Claim -> vp Property match

		// iat → issued
		if (this.jwtPayloadJson.iat != undefined && this.jwtPayloadJson.iat !== moment(this.jwtPayloadJson.vp.issued).unix()) {
			console.error('JWT iat and vp issued do not match');
			throw new Error('IAT_ISSUED_MISMATCH');
		}

		// nbf → validFrom/issuanceDate
		if(this.jwtPayloadJson.nbf != undefined && this.jwtPayloadJson.nbf != moment(this.jwtPayloadJson.vp.validFrom).unix()){
			console.error('JWT nbf and vp validFrom do not match');
			throw new Error('NBF_VALIDFROM_MISMATCH');
		}
		// if(this.jwtPayloadJson.nbf != moment(this.jwtPayloadJson.vp.issuanceDate).unix()){
		// 	throw new Error('JWT nbf and vp issuanceDate do not match');
		// }

		// exp → expirationDate
		if(this.jwtPayloadJson.exp != undefined && this.jwtPayloadJson.exp !== moment(this.jwtPayloadJson.vp.expirationDate).unix()){
			if(this.jwtPayloadJson.exp !== undefined || this.jwtPayloadJson.vp.expirationDate !== undefined ){
				console.error('JWT exp and vp expirationDate do not match');
				throw new Error('EXP_EXPIRATIONDATE_MISMATCH');
			}
		}

		// jti → id
		if(this.jwtPayloadJson.jti != undefined && this.jwtPayloadJson.jti !== this.jwtPayloadJson.vp.id){
			console.error('JWT jti and vp id do not match');
			throw new Error('JTI_VPID_MISMATCH');
		}

		// iss → issuer
		if(this.jwtPayloadJson.iss != this.jwtPayloadJson.vp.issuer){
			console.error('JWT iss and vp issuer do not match');
			throw new Error('ISS_VPISSUER_MISMATCH');
		}

		// // sub → credentialSubject.id
		// if(this.jwtPayloadJson.sub != this.jwtPayloadJson.vp.credentialSubject.id){
		// 	throw new Error('JWT sub and vp credentialSubject.id do not match');
		// }

	}



	private async vpJwtSchemaValidation() {

		const axiosTimeout: number = 5000;

		// Get current schema
		const schemaUri = this.jwtPayloadJson.vp.credentialSchema.id;

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
		const valid = validate(this.jwtPayloadJson.vp);
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

			console.error('VP failed to pass JSON Schema validation. Errors: \n'+errorStr);
			throw new Error('VP_SCHEMA_VALIDATION_FAIL');
		}
		return true;
	}
}

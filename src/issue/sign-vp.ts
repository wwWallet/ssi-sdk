import { KeyLike, SignJWT } from "jose";
import crypto from "crypto"
import { JsonWebKey2020, Secp256k1KeyPair } from "@transmute/secp256k1-key-pair";
import { JWS } from "@transmute/jose-ld";

/**
 * @example
 * ```
 * 	const vpjwt = await new SignVerifiablePresentationJWT()
 *		.setProtectedHeader({ alg: "ES256K", typ: "JWT" })
 *		.setAudience(wallet.did)
 *		.setIssuer(wallet.did)
 *		.setHolder(wallet.did)
 *		.setNonce("1233efw23d2e4f4f")
 *		.setVerifiableCredential([vcjwt])
 *		.sign(holderPrivateKey);
 * ```
 */
export class SignVerifiablePresentationJWT extends SignJWT {


	private vp: {
		"@context": string[];
		type: string[];
		holder: string;
		id: string;
		audience: string | string[];
		verifiableCredential: any[];
		issuanceDate: string;
		issuer: string;
		issued: string;
		validFrom: string;
		expirationDate: string;
		credentialSchema: {
			id: string;
			type: string;
		}
	};
	/**
	 * 
	 * @param verifiableCredential must be in jwt_vc format or array of jwt_vc
	 */
	constructor() {
		super({});

		// This pre-initialization of jwt.vp attribute, maintains structure of the vp
		this.vp = {
			"@context": [],
			type: [],
			holder: "",
			id: "",
			verifiableCredential: [],
			issuer: "",
			audience: "",
			issued: "",
			issuanceDate: "",
			validFrom: "",
			expirationDate: "",
			credentialSchema: {
				id: "",
				type: ""
			}
		};
	}

	setVerifiableCredential(verifiableCredential: any[]): this {
		this.vp.verifiableCredential = verifiableCredential;
		return this;
	}

	override setAudience(audience: string | string[]): this {
		super.setAudience(audience);
		this.vp.audience = audience;
		return this;
	}

	setHolder(holder: string): this {
		this.vp.holder = holder;
		return this;
	}

	override setIssuer(issuer: string): this {
		super.setIssuer(issuer);
		this.vp.issuer = issuer;
		return this;
	}

	override setJti(jwtId: string): this {
		super.setJti(jwtId);
		this.vp.id = jwtId;
		return this;
	}

	override setIssuedAt(input?: number): this {
		super.setIssuedAt(input);	// this function sets iat
		if(this._payload.iat) {	// due to the above line, these are safe
			super.setNotBefore(this._payload.iat);
			this.vp["issuanceDate"] = new Date(this._payload.iat * 1000).toISOString();
			this.vp["issued"] = new Date(this._payload.iat * 1000).toISOString();
			this.vp["validFrom"] = new Date(this._payload.iat * 1000).toISOString();
		}
		return this;
	}

	setNonce(nonce: string): this {
		this._payload["nonce"] = nonce;
		return this;
	}

	setCredentialSchema(schemaUri: string, type: string = "FullJsonSchemaValidator2021"): this {
		this.vp.credentialSchema = {
			id: schemaUri,
			type: type
		};
		return this;
	}

	setContext(context: string[]): this {
		this.vp["@context"] = context;
		return this;
	}

	setType(type: string[]): this {
		this.vp.type = type;
		return this;
	}

	override setExpirationTime(input: string | number): this {
		super.setExpirationTime(input);		// this function sets exp
		if(this._payload.exp)	// due to the above line, this is safe
			this.vp.expirationDate = new Date(this._payload.exp * 1000).toISOString();
		return this;
	}

	override async sign(key: KeyLike | Uint8Array): Promise<string> {
		this._payload.vp = this.vp;
		const jwt = await super.sign(key, { });
		return jwt;
	}
}

export class SignVerifiablePresentationLDP {

	private payload: {
		nonce: string;
		expirationDate: string;
	};
	private vp: {
		"@context": string[];
		type: string[];
		holder: string;
		id: string;
		audience: string | string[];
		verifiableCredential: any[];
		issuanceDate: string;
		issuer: string;
		issued: string;
		validFrom: string;
		expirationDate: string;
		credentialSchema: {
			id: string;
			type: string;
		};
		proof: {
			type: string,
			cryptosuite?: string,
			created?: string,
			verificationMethod: string,
			proofPurpose: string,
			proofValue: string
		}
	};

	constructor() {
		this.payload = {
			nonce: "",
			expirationDate: ""
		};

		// This pre-initialization of vp attribute, maintains structure of the vp
		this.vp = {
			"@context": [],
			type: [],
			holder: "",
			id: "",
			verifiableCredential: [],
			issuer: "",
			audience: "",
			issued: "",
			issuanceDate: "",
			validFrom: "",
			expirationDate: "",
			credentialSchema: {
				id: "",
				type: ""
			},
			proof: {
				type: "DataIntegrityProof",
				cryptosuite: "",
				created: "",
				verificationMethod: "",
				proofPurpose: "assertionMethod",
				proofValue: ""
			}
		};
	}

	setVerifiableCredential(verifiableCredential: any[]): this {
		this.vp.verifiableCredential = verifiableCredential;
		return this;
	}

	setAudience(audience: string | string[]): this {
		this.vp.audience = audience;
		return this;
	}

	setHolder(holder: string): this {
		this.vp.holder = holder;
		return this;
	}

	setIssuer(issuer: string): this {
		this.vp.issuer = issuer;
		return this;
	}

	setJti(jwtId: string): this {
		this.vp.id = jwtId;
		return this;
	}

	setIssuedAt(date: Date): this {
		this.vp["issuanceDate"] = date.toISOString();
		this.vp["issued"] = date.toISOString();
		this.vp["validFrom"] = date.toISOString();
		return this;
	}

	setNonce(nonce: string): this {
		this.payload["nonce"] = nonce;
		return this;
	}

	setCredentialSchema(schemaUri: string, type: string = "FullJsonSchemaValidator2021"): this {
		this.vp.credentialSchema = {
			id: schemaUri,
			type: type
		};
		return this;
	}

	setContext(context: string[]): this {
		this.vp["@context"] = context;
		return this;
	}

	setType(type: string[]): this {
		this.vp.type = type;
		return this;
	}

	setExpirationTime(input: string | number): this {
		this.payload.expirationDate = input.toString();
		return this;
	}

	async sign(keys: any, cryptosuite: string): Promise<string> {
		this.vp.proof.cryptosuite = cryptosuite;
		this.vp.proof.created = new Date().toISOString();

		const dataToSign = JSON.stringify(this.vp);

		const hash = crypto.createHash('sha256').update(dataToSign).digest();
		const jsonwebkey2020: JsonWebKey2020 = {
			id: "1",
			type: 'JsonWebKey2020',
			controller: "",
			privateKeyJwk: keys.privateKeyJwk,
			publicKeyJwk: keys.publicKeyJwk
		}
		const k = await Secp256k1KeyPair.from(jsonwebkey2020);
		const signer = JWS.createSigner(k.signer(), 'ES256K', { detached: false })
		const signature = await signer.sign({ data: hash });

		this.vp.proof.proofValue = signature;

		return JSON.stringify(this.vp);
	}
}

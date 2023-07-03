import { JWTHeaderParameters, KeyLike, SignJWT, SignOptions } from "jose";

/**
 * The SignVerifiableCredentialJWT class is a utility for creating
 * Valid Compact JWS formatted JWT strings representing a Verifiable Credential.
 *
 * @example Usage
 *
 * ```ts
 * const jwtvc = await new SignVerifiableCredentialJWT()
		.setCredentialSubject(credentialSubject)
		.setContext(context)
		.setProtectedHeader({alg: alg, kid: key.id , typ: "JWT"})
		.setType(credentialType)
		.setIssuer(issuerDid)
		.setIssuedAt()
		.setSubject(holderDID)
		.setAudience(holderDID)
		.setJti(`urn:id:${randomUUID()}`)
		.setExpirationTime("1y")
		.setCredentialSchema(schemaURL, "FullJsonSchemaValidator2021")
		.sign(await importJWK(jwk, alg));
*
 * ```
 */
export class SignVerifiableCredentialJWT<CredentialSubjectType> extends SignJWT {
	private vc: {
		"@context": string[];
		type: string[];
		id: string;
		issuer: string;
		audience: string;
		issuanceDate: string;
		issued: string;
		validFrom: string;
		expirationDate?: string;
		credentialSubject: CredentialSubjectType;
		credentialSchema: {
			id: string,
			type: string
		}
	};

	constructor() {

		super({});
		// initialize jwt.vc attribute to maintain ordered structure even though jsons are unordered
		this.vc = {
			"@context": [],
			type: [],
			id: "",
			issuer: "",
			audience: "",
			issuanceDate: "",
			issued: "",
			validFrom: "",
			credentialSubject: { } as CredentialSubjectType,
			credentialSchema: {
				id: "",
				type: ""
			}
		};
	}

	setCredentialSubject(credentialSubject: any): this {
		this.vc.credentialSubject = credentialSubject;
		return this;
	}

	/**
	 * Set Verifiable Credential Issuance Date
	 * Sets "iat" (Issued At) and "nbf" (Not Before) JWT Claims.
	 * Also sets "issuanceDate", "issued", and "validFrom" VC attributes.
	 * @param input Date timestamp. Default is current timestamp.
	*/
	override setIssuedAt(input?: number): this {
		super.setIssuedAt(input);	// this function sets iat
		if(this._payload.iat) {	// due to the above line, these are safe
			super.setNotBefore(this._payload.iat);
			this.vc["issuanceDate"] = new Date(this._payload.iat * 1000).toISOString();
			this.vc["issued"] = new Date(this._payload.iat * 1000).toISOString();
			this.vc["validFrom"] = new Date(this._payload.iat * 1000).toISOString();
		}
		return this; 
	}
	 
	/**
		 * Set Verifiable Credential Expiration Time.
		 * Sets "exp" (Expireration) JWT Claim.
		 * Also sets "expirationDate" VC attribute.
		 * @param input Date timestamp, or string that describes amount of time until expiration.
		 * h for hours, d for days, m for months
		 * @example Set Verifiable Credential Expiration in 2 hours
		 * ```ts
		 	setExpirationTime('2h')
			```
		 *
		 * @example Set Verifiable Credential Expiration in 1 year
		 * ```ts
		 	setExpirationTime('1y')
		 ```
		*/
	override setExpirationTime(input: string | number): this {
		super.setExpirationTime(input);	// this function sets exp
		if(this._payload.exp)	// due to the above line, this is safe
			this.vc.expirationDate = new Date(this._payload.exp * 1000).toISOString();
		return this;
	}

	/**
	 * Set Verifiable Credential ID Value
	 * Sets "jti" (JWT ID) JWT Claim.
	 * Also sets "id" VC attribute.
	 * @param jwtId: the ID Value to be used
	*/
	override setJti(jwtId: string): this {
		super.setJti(jwtId);
		this.vc.id = jwtId;
		return this;
	}

	/**
	 * Set Verifiable Credential Issuer
	 * Sets "iss" JWT Claim.
	 * Also sets "issuer" VC attribute.
	 * @param issuer: the issuer to be set
	*/
	override setIssuer(issuer: string): this {
		super.setIssuer(issuer);
		this.vc.issuer = issuer;
		return this;
	}

	/**
	 * Set Credential Schema for Verifiable Credential
	 * Sets "credentialSchema" VC attribute.
	 * @param schemaUri: the schema URI to be set as credentialSchema ID
	 * @param type: the type of schema. Default: "FullJsonSchemaValidator2021"
	*/
	setCredentialSchema(schemaUri: string, type: string = "FullJsonSchemaValidator2021"): this {
		this.vc["credentialSchema"] = {
			id: schemaUri,
			type: type
		};
		return this;
	}

	/**
	 * Sets Verifiable Credential "@contect" attribute.
	 * @param context: The array of context URIs to be set as the "@context" attribute
	*/
	setContext(context: string[]): this {
		this.vc["@context"] = context;
		return this;
	}

	/**
	 * Sets Verifiable Credential "type" attribute.
	 * @param type: The array of types to be set as the "type" attribute
	*/
	setType(type: string[]): this {
		this.vc["type"] = type;
		return this;
	}

	/**
	 * Set Verifiable Credential Audience
	 * Sets "aud" JWT Claim.
	 * Also sets "audience" VC attribute.
	 * @param audience: the audience to be set
	*/
	override setAudience(audience: string): this {
		super.setAudience(audience);
		this.vc.audience = audience;
		return this;
	}

	/**
	 * Set JWT Protected Header
	 * @param protectedHeader: the JWT Header to be used
	 * @throws - Error if 'alg' is not defined on the header parameters
	 * @throws - Error if neither 'kid' nor 'jwk' header parameters are given
	*/
	override setProtectedHeader(protectedHeader: JWTHeaderParameters): this {
		if (protectedHeader.alg == undefined)
			throw new Error("alg is not defined on jwt header");
		if (protectedHeader.kid == undefined && protectedHeader.jwk == undefined)
			throw new Error("'kid' or 'jwk' must be defined");
		super.setProtectedHeader(protectedHeader);
		return this;	
	}

	/**
	 * Signs and returns the JWT.
	 * @param key Private Key or Secret to sign the JWT with.
	 * @param options JWT Sign options.
	*/
	override async sign(key: KeyLike | Uint8Array, options?: SignOptions): Promise<string> {
		this._payload.vc = this.vc;
		const jwt = await super.sign(key, options);
		return jwt;
	}

}
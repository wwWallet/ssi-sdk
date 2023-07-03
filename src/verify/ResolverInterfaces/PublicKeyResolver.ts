import { JWK } from "jose";

// Targer interface
export interface PublicKeyResolver {
	/**
	 * @throws
	 * @param verificationMethod (ledger agnostic)
	 * For VC JWTs, the verificationMethod is located in the "kid" of the header
	 * For VC JSON-LDs the verificationMethod is located at the proof.verificationMethod
	 */
	getPublicKeyJwk(verificationMethod: string): Promise<JWK>;
}




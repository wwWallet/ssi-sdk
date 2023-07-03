import { JWK } from "jose";

export interface Key {
	id: string;   // must be in format did:ebsi:dsfwr243fdf#key-2
	publicKeyJwk: JWK;
	privateKeyJwk: JWK;
	publicKeyEncryptionJwk: JWK;
	privateKeyEncryptionJwk: JWK;
}

/**
 * @enum
 */
export const AlgorithmAliases = {
	ES256K: "JsonWebKey2020",
	ES256: "JsonWebKey2020",
	RS256: "JsonWebKey2020",
	EdDSA: "JsonWebKey2020",
} as const;

/**
 * 
 * @example
 * ```
 * {
 * 	"ES256K": {
 * 			publicKeyJwk: ...	
 * 			privateKeyJwk: ...
 * 			...
 * 	},
 * 	"RS256": {
 * 			...
 * 	}
 * }
 * ```
 */
export type WalletExportedKeys = {
	[algorithm: string]: Key;
}
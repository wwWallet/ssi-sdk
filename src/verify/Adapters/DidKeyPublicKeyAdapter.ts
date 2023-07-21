import { JWK } from "jose";
import { PublicKeyResolver } from "../ResolverInterfaces/PublicKeyResolver";
import { Resolver } from "did-resolver";
import { util, getResolver } from '@cef-ebsi/key-did-resolver';

export class DidKeyPublicKeyAdapter implements PublicKeyResolver {
	
	async getPublicKeyJwk(verificationMethod: string): Promise<JWK> {
		const did = verificationMethod.split('#')[0];
		const didMethod = verificationMethod.split(':')[1];

		if (didMethod != 'key') {
			throw new Error(`DID method "${didMethod}" is not supported by the adapter DidKeyPublicKeyAdapter`);
		}

		try {
			util.validateDid(did);
		}
		catch (error) {
			console.error('Error in DidKeyPublicKeyAdapter: Unable to get public key from did - invalid did');
			console.error(`did: ${did}, error: ${error}`);
			throw new Error('INVALID_DID');
		}

		const keyResolver = getResolver();
		const didResolver = new Resolver(keyResolver);

		const doc = await didResolver.resolve(did);
		if (doc.didDocument?.verificationMethod)
			if (doc.didDocument?.verificationMethod[0].publicKeyJwk)
				return doc.didDocument?.verificationMethod[0].publicKeyJwk as JWK;
			else
				console.error('Public Key JWK is undefined');
		else
			console.error('Verification method is undefined');

		throw new Error('Error fetching public key');
	}
}

export const didKeyPublicKeyAdapter = new DidKeyPublicKeyAdapter();
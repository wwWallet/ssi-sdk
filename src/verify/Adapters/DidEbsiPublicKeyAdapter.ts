import { JWK } from "jose";
import { PublicKeyResolver } from "../ResolverInterfaces/PublicKeyResolver";
import { Resolver } from "did-resolver";
import { getResolver } from '@cef-ebsi/ebsi-did-resolver';

export class DidEbsiPublicKeyAdapter implements PublicKeyResolver {
	
	async getPublicKeyJwk(verificationMethod: string): Promise<JWK> {
		const did = verificationMethod.split('#')[0];
		const didMethod = verificationMethod.split(':')[1];

		if (didMethod != 'ebsi') {
			throw new Error(`DID method "${didMethod}" is not supported by the adapter DidEbsiPublicKeyAdapter`);
		}

		const resolverConfig = {
			registry: "https://api-pilot.ebsi.eu/did-registry/v4/identifiers",
		};

		const keyResolver = getResolver(resolverConfig);
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

export const didEbsiPublicKeyAdapter = new DidEbsiPublicKeyAdapter();
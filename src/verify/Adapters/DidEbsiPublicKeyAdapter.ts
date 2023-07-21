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

// const body = response.data;
// let verificationMethodsSearch = body.verificationMethod.filter((vm: { id: string; }) => vm.id == verificationMethod);
// if (verificationMethodsSearch.length != 0) {
// 	verificationMethodsSearch = verificationMethodsSearch[0];
// }
// else {
// 	throw new Error("Error in EBSIPublicKeyAdapter: Failed to find the verification method on the EBSI DID Registry");
// }

// if (!verificationMethodsSearch.publicKeyJwk) {
// 	throw new Error("Error in EBSIPublicKeyAdapter: 'publicKeyJwk' attribute does not exist on verification method");
// }
// return verificationMethodsSearch.publicKeyJwk as JWK;
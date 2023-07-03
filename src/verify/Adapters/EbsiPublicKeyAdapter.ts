import { JWK } from "jose";
import { PublicKeyResolver } from "../ResolverInterfaces/PublicKeyResolver";
import axios from "axios";
import { getPublicKeyFromDid } from "../../wallet";


export class EbsiPublicKeyAdapter implements PublicKeyResolver {
	
	
	async getPublicKeyJwk(verificationMethod: string): Promise<JWK> {
		const did = verificationMethod.split('#')[0];
		const didMethod = verificationMethod.split(':')[1];


		if (didMethod == 'key') {
			const jwk = await getPublicKeyFromDid(didMethod);
			return jwk;
		}

		if (didMethod != 'ebsi') {
			throw new Error(`DID method "${didMethod}" is not supported by the adapter EbsiPublicKeyAdapter`);
		}

		let response;
		try {
			response = await axios.get("https://api-pilot.ebsi.eu/did-registry/v4/identifiers/"+did);
		}
		catch(e) {
			throw new Error("Error in EBSIPublicKeyAdapter: Failed to lookup the EBSI DID registry for the public key");
		}
		const body = response.data;
		let verificationMethodsSearch = body.verificationMethod.filter((vm: { id: string; }) => vm.id == verificationMethod);
		if (verificationMethodsSearch.length != 0) {
			verificationMethodsSearch = verificationMethodsSearch[0];
		}
		else {
			throw new Error("Error in EBSIPublicKeyAdapter: Failed to find the verification method on the EBSI DID Registry");
		}

		if (!verificationMethodsSearch.publicKeyJwk) {
			throw new Error("Error in EBSIPublicKeyAdapter: 'publicKeyJwk' attribute does not exist on verification method");
		}
		return verificationMethodsSearch.publicKeyJwk as JWK;

	}

}

export const ebsiPublicKeyAdapter = new EbsiPublicKeyAdapter();
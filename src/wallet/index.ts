import * as jose from 'jose';
import { JWK } from 'jose';
import { Resolver } from 'did-resolver';
import { util, getResolver } from '@cef-ebsi/key-did-resolver';

export type WalletKey = {
	privateKey: JWK,
	publicKey: JWK,
	did: string,
	alg: string,
	verificationMethod: string,
}



export class NaturalPersonWallet {

	key: WalletKey = { privateKey: {}, publicKey: {}, did: "", alg: "", verificationMethod: "" };

	public async createWallet(alg: 'ES256'): Promise<this> {
		const { publicKey, privateKey } = await jose.generateKeyPair(alg);

		const publicKeyJWK = await jose.exportJWK(publicKey);
		const privateKeyJWK = await jose.exportJWK(privateKey);

		const did = util.createDid(publicKeyJWK);

		const w = {
			privateKey: privateKeyJWK,
			publicKey: publicKeyJWK,
			did: did,
			alg: alg,
			verificationMethod: did + "#" + did.split(':')[2]
		}
		this.key = w;
		return this;
	}

	public getPrivateKey(): JWK {
		return this.key?.privateKey as JWK
	}
	public getPublicKey(): JWK {
		return this.key?.publicKey as JWK
	}

	public static async initializeWallet(key: WalletKey): Promise<NaturalPersonWallet> {
		const np = new NaturalPersonWallet()
		np.key = key
		return np;
	}
}

export async function getPublicKeyFromDid(did: string): Promise<JWK> {
	try {
			util.validateDid(did);
		}
		catch(error) {
			console.error('Unable to get public key from did: invalid did');
			console.error(`did: ${did}, error: ${error}`);
			throw new Error('INVALID_DID');
		}

		const keyResolver = getResolver();
		const didResolver = new Resolver(keyResolver);

		const doc = await didResolver.resolve(did);

		if(doc.didDocument?.verificationMethod)
			if (doc.didDocument?.verificationMethod[0].publicKeyJwk)
				return doc.didDocument?.verificationMethod[0].publicKeyJwk;
			else
				console.error('Public Key JWK is undefined');
		else
			console.error('Verifrication method is undefined');
		
		throw new Error('Error fetching public key');
}
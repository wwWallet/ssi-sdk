import * as jose from 'jose';
import { JWK } from 'jose';
import PublicKeyResolverBuilder from '../verify/PublicKeyResolverBuilder';
import { didKeyPublicKeyAdapter } from '../verify/Adapters/DidKeyPublicKeyAdapter';
import { didEbsiPublicKeyAdapter } from '../verify/Adapters/DidEbsiPublicKeyAdapter';
import { util } from '@cef-ebsi/key-did-resolver';

export type WalletKey = {
	privateKey: JWK,
	publicKey: JWK,
	did: string,
	alg: string,
	verificationMethod: string,
}

const resolverBuilder = new PublicKeyResolverBuilder()
	.addPublicKeyResolver(didKeyPublicKeyAdapter)
	.addPublicKeyResolver(didEbsiPublicKeyAdapter);

export class NaturalPersonWallet {

	key: WalletKey = { privateKey: {}, publicKey: {}, did: "", alg: "", verificationMethod: "" };

	public async createWallet(alg: string = "ES256"): Promise<this> {
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
		const publicKeyJwk: JWK | null = await resolverBuilder.resolve(did);

		if (!publicKeyJwk) {
			throw new Error("Couldn't resolve the public key for the DID");
		}
		console.log('Resolved Public Key:', publicKeyJwk);
		return publicKeyJwk;
	} catch (error) {
		console.error('Error resolving public key:', error);
		throw new Error("Couldn't resolve the public key for the DID");
	}
}
import { PublicKeyResolver } from './ResolverInterfaces/PublicKeyResolver';
import { JWK } from "jose";

class PublicKeyResolverBuilder {
	private publicKeyResolvers: PublicKeyResolver[] = [];

	public addPublicKeyResolver(pkResolver: PublicKeyResolver): this {
		this.publicKeyResolvers.push(pkResolver);
		return this;
	}

	async resolve(verificationMethod: string): Promise<JWK | null> {
		for (const resolver of this.publicKeyResolvers) {
			try {
				const publicKey = await resolver.getPublicKeyJwk(verificationMethod);
				if (publicKey) {
					return publicKey;
				}
			} catch (error) {
				console.error('Error resolving public key:', error);
				throw new Error('Error resolving public key')
			}
		}

		return null;
	}
}

export default PublicKeyResolverBuilder;
import { importJWK } from "jose";

import { SignVerifiableCredentialJWT, NaturalPersonWallet, SignVerifiablePresentationJWT, JwtVP, VC, ebsiPublicKeyAdapter, ebsiTrustedIssuerAdapter } from '../src';


describe("Issuance Testing", () => {
	test("Main test", async () => {
		// create two wallets
		const wallet = await new NaturalPersonWallet().createWallet("ES256"); 
		const wallet2 = await new NaturalPersonWallet().createWallet("ES256"); 

		// wallet issues vc for wallet2
		const credentialSubject = {
			id: wallet2.key.did,
			firstName: "George",
			issuer: wallet.key.did,
			familyName: "Kanelopoulos",
			achieved: {
				id: "urn:diploma:uoa:123",
				title: "BSc Computer Science Degree"
			}
		};

		const issuerPrivateKey = await importJWK(wallet.key.privateKey, wallet.key.alg);

		const vcjwt = await new SignVerifiableCredentialJWT()
			.setCredentialSubject(credentialSubject)
			.setExpirationTime('10y') // expires in 10 years
			.setSubject(wallet2.key?.did)
			.setJti("123xxx")
			.setIssuedAt()
			.setIssuer(wallet.key.did)
			.setAudience(wallet2.key.did)
			.setProtectedHeader({ alg: wallet.key.alg, typ: "JWT", kid: wallet.key.verificationMethod })
			.sign(issuerPrivateKey);




		// Verify a VC (minimal setup)
		const vc = VC.vcBuilder(vcjwt)
			.addLegalEntityResolver(ebsiTrustedIssuerAdapter)
			.addPublicKeyResolver(ebsiPublicKeyAdapter);
		const res = await vc.verify({
			signatureValidation: false,
			schemaValidation: false,
			attributeMappingValidation: true,
			constraintValidation: true
		});

		expect(res.result).toBe(true);

		// assume that holder is the issuer
		const holderPrivateKey = issuerPrivateKey;
		const vpjwt = await new SignVerifiablePresentationJWT()
			.setProtectedHeader({ alg: wallet.key.alg, typ: "JWT", kid: wallet.key.verificationMethod })
			.setAudience(wallet.key.did)
			.setIssuer(wallet.key.did)
			.setHolder(wallet.key.did)
			.setNonce("1233efw23d2e4f4f")
			.setVerifiableCredential([ vcjwt ])
			.sign(holderPrivateKey);
			
		const vp = new JwtVP(vpjwt);
		await vp.verify(wallet.key.did, {
			schemaValidation: false,
			signatureValidation: false,
			constraintValidation: false
		});
	})

})
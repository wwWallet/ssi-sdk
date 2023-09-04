import { importJWK} from "jose";
import { SignVerifiableCredentialJWT, SignVerifiableCredentialJsonLD, NaturalPersonWallet, SignVerifiablePresentationJWT, JwtVP, VC, ebsiTrustedIssuerAdapter, SignVerifiablePresentationLDP, LdpVP } from '../src';

import * as secp256k1 from '@transmute/did-key-secp256k1';
import crypto from 'crypto';

describe("Issuance JWT Testing", () => {
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
			.addLegalEntityResolver(ebsiTrustedIssuerAdapter);
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

describe("Issuance LDP Testing", () => {
	test("Main test", async () => {

		let { didDocument: didDocumentIssuer, keys: keysIssuer } = await secp256k1.generate(
			{
				secureRandom: () => {
					return crypto.randomBytes(32);
				},
			},
			{ accept: 'application/did+json' }
		);
		
		let { didDocument: didDocument2 } = await secp256k1.generate(
			{
				secureRandom: () => {
					return crypto.randomBytes(32);
				},
			},
			{ accept: 'application/did+json' }
		);

		const credentialSubject = {
			id: didDocument2.id,
			firstName: "George",
			issuer: didDocumentIssuer.id,
			familyName: "Kanelopoulos",
			achieved: {
				id: "urn:diploma:uoa:123",
				title: "BSc Computer Science Degree"
			}
		};

		const verificationMethod = didDocumentIssuer.id + '#' + didDocumentIssuer.id.split(':')[2]
		const vcldp = await new SignVerifiableCredentialJsonLD()
			.setCredentialSubject(credentialSubject)
			.setContext(["https://w3id.org/security/data-integrity/v1", "https://w3id.org/security/v1"])
			.setJti("123xxx")
			.setIssuedAt(new Date())
			.setIssuer(didDocumentIssuer.id)
			.setAudience(didDocument2.id)
			.setVerificationMethod(verificationMethod)
			.sign(keysIssuer[0], "EcdsaSecp256k1Signature2019");

		console.log("VCLDP is: ", vcldp);
		expect(vcldp).toBeTruthy();

		// Verify a VC (minimal setup)
		const vc = VC.vcBuilder(vcldp)
			.addLegalEntityResolver(ebsiTrustedIssuerAdapter);
		const res = await vc.verify({
			signatureValidation: false,
			schemaValidation: false,
			attributeMappingValidation: false,
			constraintValidation: false,
			keys: keysIssuer[0]
		});
		console.log("res: ", res)
		expect(res.result).toBe(true);

		// // Moved in verify function
		// const jsonwebkey2020: JsonWebKey2020 = {
		// 	id: "1",
		// 	type: 'JsonWebKey2020',
		// 	controller: "",
		// 	privateKeyJwk: keysIssuer[0].privateKeyJwk,
		// 	publicKeyJwk: keysIssuer[0].publicKeyJwk
		// }
		// const k = await Secp256k1KeyPair.from(jsonwebkey2020);
		// const verifier = JWS.createVerifier(k.verifier(), 'ES256K', {
		// 	detached: false,
		// });
		// const verified = await verifier.verify({
		// 	data: JSON.parse(vcldp),
		// 	signature: JSON.parse(vcldp).proof.proofValue,
		// });
		// console.log("verified: ", verified)
		
		
		
		
		// assume that holder is the issuer
		const ebsiVerifiablePresentationSchemaURL = "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/zFj7VdCiHdG4GB6fezdAUKhDEuxFR2bri2ihKLkiZYpE9";

		// 	const holderPrivateKey = issuerPrivateKey;
		const vpldp = await new SignVerifiablePresentationLDP()
			.setAudience(didDocumentIssuer.id)
			.setType(["VerifiablePresentation"])
			.setContext(["https://w3id.org/security/data-integrity/v1", "https://w3id.org/security/v1"])
			.setCredentialSchema(
				ebsiVerifiablePresentationSchemaURL, 
				"FullJsonSchemaValidator2021")
			.setIssuer(didDocumentIssuer.id)
			.setHolder(didDocumentIssuer.id)
			.setNonce("1233efw23d2e4f4f")
			.setExpirationTime('1m')
			.setVerificationMethod(verificationMethod)
			.setVerifiableCredential([vcldp])
			.sign(keysIssuer[0], "EcdsaSecp256k1Signature2019");
		console.log("vpldp: ", vpldp)

		const vp = new LdpVP(vpldp);
		await vp.verify(didDocumentIssuer.id, {
			schemaValidation: false,
			signatureValidation: false,
			constraintValidation: false,
			keys: keysIssuer[0]
		});

	})
})
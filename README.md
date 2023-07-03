
<h1 align="center">
  <br>
  <a href="https://ediplomas.gr"><img src="https://ediplomas.gr/static/media/eDiplomasLogo.4c1b3fe7.svg" alt="eDiplomas" width="100"></a>
  <br><center>Self-Sovereign Identity SDK</center>
  <br>
</h1>
<br>

> An npm package ready to be used for applications(wallets) which extend the EBSI ecosystem.

## Installation

```
yarn add @gunet/ssi-sdk
```

For npm:

```
npm i @gunet/ssi-sdk
```



## Usage


```typescript
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
			.setProtectedHeader({ alg: wallet.key.alg, typ: "JWT", kid: wallet.key.did })
			.sign(issuerPrivateKey);


		// Verify a VC (minimal setup)
		const vc = VC.vcBuilder(vcjwt);
		await vc.verify({
			signatureValidation: false,
			schemaValidation: true,
			attributeMappingValidation: true,
			constraintValidation: true
		});

		// assume that holder is the issuer
		const holderPrivateKey = issuerPrivateKey;
		const vpjwt = await new SignVerifiablePresentationJWT()
			.setProtectedHeader({ alg: wallet.key.alg, typ: "JWT", kid: wallet.key.did })
			.setAudience(wallet.key.did)
			.setIssuer(wallet.key.did)
			.setHolder(wallet.key.did)
			.setNonce("1233efw23d2e4f4f")
			.setVerifiableCredential([vcjwt])
			.sign(holderPrivateKey);
			
		const vp = new JwtVP(vpjwt);
		await vp.verify(wallet.key.did, {
			schemaValidation: false,
			signatureValidation: false,
			constraintValidation: false
		});
```

## [Documentation](https://open.gunet.gr/ssi-pack)

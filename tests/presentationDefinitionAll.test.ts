import { importJWK } from "jose";
import { NaturalPersonWallet, SignVerifiableCredentialJWT, SignVerifiablePresentationJWT, Verify } from "../src";

var wallet: NaturalPersonWallet;
var nationalIdVC: string;
var europassVC: string;
var vp1: string; // contains nationalIdVC only
var vp2: string; // contains both nationalIdVC and europassVC
var vp3: string; // contains two nationalIdVCs and once europassVC

var presentationDefinitionWithTwoDescriptors = {
	"id": "Example Definition",
	"format": { "jwt_vc": { alg: [ 'ES256' ] } },
	"input_descriptors": [
		{
			"id": "NationalID",

			"constraints": {
				"fields": [
					{
						"path": [
							"$.credentialSchema.id"
						],
						"filter": {
							"type": "string",
							"const": "https://api-pilot.ebsi.eu/national-id-schema.json"
						}
					},
					{
						"path": [
							"$.credentialSubject.personalIdentifier"
						],
						"filter": { 
							"type": "string"
						}
					}
				]
			}
		},
		{
			"id": "Europass",
			"constraints": {
				"fields": [
					{
						"path": [
							"$.credentialSchema.id"
						],
						"filter": {
							"type": "string",
							"const": "https://api-pilot.ebsi.eu/europass-random-schema.json"
						}
					}
				]
			}
		}
	]
};


const presentationDefinitionWithTypeConstraint = {
	"id": "Example Definition",
	"format": { "jwt_vc": { alg: [ 'ES256' ] } },
	"input_descriptors": [
		{
			"id": "VerifiableID",
			"constraints": {
				"fields": [
					{
						"path": [ '$.type' ],
						"filter": {
							"type": 'array',
							"contains": { "const": "VerifiableID" }
						}
					}
				]
			}
		}
	]
}

beforeAll(async () => {
	wallet = await new NaturalPersonWallet().createWallet("ES256");
	nationalIdVC = await new SignVerifiableCredentialJWT()
		.setType(["VerifiableID"])
		.setCredentialSubject({ id: "123xxx", personalIdentifier: "urn:gr:1234" })
		.setCredentialSchema("https://api-pilot.ebsi.eu/national-id-schema.json")
		.setProtectedHeader({ alg: "ES256", kid: wallet.key.did + "#" + wallet.key.did.split(":")[2] })
		.sign(await importJWK(wallet.getPrivateKey(), "ES256"));


	europassVC = await new SignVerifiableCredentialJWT()
		.setCredentialSubject({ id: "456xxx" })
		.setCredentialSchema("https://api-pilot.ebsi.eu/europass-random-schema.json")
		.setProtectedHeader({ alg: "ES256", kid: wallet.key.did + "#" + wallet.key.did.split(":")[2] })
		.sign(await importJWK(wallet.getPrivateKey(), "ES256"));

	vp1 = await new SignVerifiablePresentationJWT()
		.setVerifiableCredential([ nationalIdVC ])
		.setProtectedHeader({ alg: "ES256", kid: wallet.key.did + "#" + wallet.key.did.split(":")[2] })
		.sign(await importJWK(wallet.getPrivateKey(), "ES256"));

	vp2 = await new SignVerifiablePresentationJWT()
		.setVerifiableCredential([ nationalIdVC, europassVC ])
		.setProtectedHeader({ alg: "ES256", kid: wallet.key.did + "#" + wallet.key.did.split(":")[2] })
		.sign(await importJWK(wallet.getPrivateKey(), "ES256"));

	vp3 = await new SignVerifiablePresentationJWT()
		.setVerifiableCredential([ nationalIdVC, europassVC ])
		.setProtectedHeader({ alg: "ES256", kid: wallet.key.did + "#" + wallet.key.did.split(":")[2] })
		.sign(await importJWK(wallet.getPrivateKey(), "ES256"));
})






describe("Presentation Definition", () => {
	
	test("Should generate presentation submission with one VC", async () => {
		const result = await Verify.getMatchesForPresentationDefinition(vp1, presentationDefinitionWithTwoDescriptors);
		expect(result).not.toBeNull();
		if (!result)
			return;

		const { conformingCredentials, presentationSubmission } = result;
		expect(conformingCredentials).toEqual([ nationalIdVC ]);

		expect(presentationSubmission.definition_id).toEqual(presentationDefinitionWithTwoDescriptors.id);
		expect(presentationSubmission.descriptor_map).toEqual([
			{
				id: "NationalID",
				format: "jwt_vc",
				path: "$.verifiableCredential[0]",
			}
		]);
	})


	test("Should generate presentation submission with two VCs", async () => {
		const result = await Verify.getMatchesForPresentationDefinition(vp2, presentationDefinitionWithTwoDescriptors);
		expect(result).not.toBeNull();

		if (!result)
			return;

		const { conformingCredentials, presentationSubmission } = result;
		expect(conformingCredentials).toEqual([ nationalIdVC, europassVC ]);

		expect(presentationSubmission.definition_id).toEqual(presentationDefinitionWithTwoDescriptors.id);
		expect(presentationSubmission.descriptor_map).toEqual([
			{
				id: "NationalID",
				format: "jwt_vc",
				path: "$.verifiableCredential[0]",
			},
			{
				id: "Europass",
				format: "jwt_vc",
				path: "$.verifiableCredential[1]",
			}
		]);
	})


	test("Function Verify.verifyVcJwtWithDescriptor", async () => {
		const verification1 = Verify.verifyVcJwtWithDescriptor(presentationDefinitionWithTwoDescriptors.input_descriptors[0], nationalIdVC);
		expect(verification1).toBeTruthy();
		const verification2 = Verify.verifyVcJwtWithDescriptor(presentationDefinitionWithTwoDescriptors.input_descriptors[0], europassVC);
		expect(verification2).toBeFalsy();
	})


	test("Pass verification when checking with types", async () => {
		const { conformingCredentials, presentationSubmission} = await Verify.getMatchesForPresentationDefinition(vp3, presentationDefinitionWithTypeConstraint)
	
		expect(conformingCredentials.length).toEqual(1);

		expect(presentationSubmission.descriptor_map).toEqual([
			{
				id: "VerifiableID",
				format: "jwt_vc",
				path: "$.verifiableCredential[0]",
			}
		])
	})
})
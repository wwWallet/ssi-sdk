import axios from "axios";
import { LegalEntityResolver } from "../ResolverInterfaces/LegalEntityResolver";


export class EbsiTrustedIssuerAdapter implements LegalEntityResolver {
	async isLegalEntity(legalEntityIdentifier: string): Promise<boolean> {
		try {
			await axios.get("https://api-pilot.ebsi.eu/trusted-issuers-registry/v4/issuers/"+legalEntityIdentifier);
			return true;
		}
		catch(e) {
			return false;
		}
	}
}

export const ebsiTrustedIssuerAdapter = new EbsiTrustedIssuerAdapter();
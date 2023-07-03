// Target interface
export interface LegalEntityResolver {

	/**
	 * @throws
	 * @param legalEntityIdentifier 
	 */
	isLegalEntity(legalEntityIdentifier: string): Promise<boolean>;
}



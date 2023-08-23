export type VerifyOptions = {
	constraintValidation?: boolean;
	signatureValidation?: boolean;
	attributeMappingValidation?: boolean; // for jwt
	schemaValidation?: boolean;
	keys?: any; // for ldp
}

export type DetailedVerifyResults = {
	constraintValidation?: boolean;
	signatureValidation?: boolean;
	attributeMappingValidation?: boolean;
	schemaValidation?: boolean;
}

export const defaultVerifyOptions: VerifyOptions = {
	constraintValidation: true,
	signatureValidation: true,
	attributeMappingValidation: true,
	schemaValidation: true,
}



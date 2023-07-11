# FIDO implementation using TPM on iOS

Passkey forces you to store your private key in the iCloud keychain, without giving the developer or users an option to choose TPM. This is a demo project to show how to implement the FIDO protocol with the Local Authentication API, and leverage the TPM module for key storage. If follow the FIDO protocol closely, this implementation could achieve NIST AAL3 level of security assurance. 

//
//*----------------------------------------------------------------------------
//
//  Copyright (c) 1999-2017 Logitech, Inc.  All Rights Reserved
//
//  This program is a trade secret of LOGITECH, and it is not to be reproduced,
//  published, disclosed to others, copied, adapted, distributed or displayed
//  without the prior authorization of LOGITECH.
//
//  Licensee agrees to attach or embed this notice on all copies of the program,
//  including partial copies or modified versions thereof.
//
//  Description: For RSA signature verification
//--------------------------------------------------------------------------------
//
// verifyrsa.h
//

#ifdef __cplusplus
extern "C" {
#endif

#ifdef VERIFYRSA_EXPORTS
#define VERIFYRSA_API __declspec(dllexport)
#else
#define VERIFYRSA_API __declspec(dllimport)
#endif

/**
* @brief Verify rsa signature module. You will need to provide your public key for this function to work.  See publicKey.h
* @param publicKey	- the public key
* @param publicKeyLen
* @param message	the message to verify
* @param messageLen
* @param base64Signature	the base64 signature (no newline).
* @param base64SignatureLen
* @return Returns true if message has been verified using the signature
*/
VERIFYRSA_API bool verifyRSASignature(
	const char* publicKey,
	size_t publicKeyLen,
	unsigned char* message,
	size_t messageLen,
	unsigned char* base64Signature,
	size_t base64SignatureLen);

#ifdef __cplusplus
}
#endif

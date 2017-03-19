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
// verifyrsa.cpp
//

#include "stdafx.h"
#include "verifyrsa.h"

#include <assert.h>
#include <openssl\aes.h>
#include <openssl\evp.h>
#include <openssl\rsa.h>
#include <openssl\pem.h>
#include <openssl\ssl.h>
#include <openssl\bio.h>
#include <openssl\err.h>

// not used.  Just here for reference
void Encode(const unsigned char* in, size_t in_len,
	char** out, size_t* out_len)
{
	BIO *buff, *b64f;
	BUF_MEM *ptr;

	b64f = BIO_new(BIO_f_base64());
	buff = BIO_new(BIO_s_mem());
	buff = BIO_push(b64f, buff);

	BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
	BIO_set_close(buff, BIO_CLOSE);
	BIO_write(buff, in, in_len);
	BIO_flush(buff);

	BIO_get_mem_ptr(buff, &ptr);
	(*out_len) = ptr->length;
	(*out) = (char *)malloc(((*out_len) + 1) * sizeof(char));
	memcpy(*out, ptr->data, (*out_len));
	(*out)[(*out_len)] = '\0';

	BIO_free_all(buff);
}

void Decode(const unsigned char* in, size_t in_len,
	unsigned char** out, size_t* out_len)
{
	BIO *buff, *b64f;

	b64f = BIO_new(BIO_f_base64());
	buff = BIO_new_mem_buf((void *)in, in_len);
	buff = BIO_push(b64f, buff);
	(*out) = (unsigned char *)malloc(in_len * sizeof(char));

	BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
	BIO_set_close(buff, BIO_CLOSE);
	(*out_len) = BIO_read(buff, (*out), in_len);
	(*out) = (unsigned char *)realloc((void *)(*out), ((*out_len) + 1) * sizeof(unsigned char));
	(*out)[(*out_len)] = '\0';

	BIO_free_all(buff);
}

/**
* @brief verifyRSASignature
* @param publicKey	- the public key
* @param publicKeyLen
* @param message	the message to verify
* @param messageLen
* @param base64Signature	the base signature (no newline). 
* @param base64SignatureLen
* @return Returns true if message has been verified using the signature
*/
VERIFYRSA_API bool verifyRSASignature(
	const char* publicKey,
	size_t publicKeyLen,
	unsigned char* message,
	size_t messageLen,
	unsigned char* base64Signature,
	size_t base64SignatureLen)
{
	if (publicKey == NULL ||
		message == NULL ||
		base64Signature == NULL)
		return false;

	bool ret = false;

	//Decode the signature
	unsigned char* signature = NULL;
	size_t signatureLen = 0;
	Decode(base64Signature, base64SignatureLen, &signature, &signatureLen);
	if (signature == NULL)
		return false;

	// Create the RSA object
	RSA *rsa = NULL;
	BIO *keybio;
	const char* c_string = publicKey;
	keybio = BIO_new_mem_buf((void*)c_string, -1);
	if (keybio == NULL) {
		ret = false;
		goto CLEANUP;
	}
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	if (rsa == NULL) {
		ret = false;
		goto CLEANUP;
	}

	EVP_PKEY* pubKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubKey, rsa);
	EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
		ret = false;
		goto CLEANUP;
	}
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, message, messageLen) <= 0) {
		ret = false;
		goto CLEANUP;
	}
	int status = EVP_DigestVerifyFinal(m_RSAVerifyCtx, signature, signatureLen);
	if (status == 1) {
		ret = true;
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
	}
	else if (status == 0){
		ret = false;
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
	}
	else{
		ret = false;
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
	}

CLEANUP:
	if (signature != NULL)
		free(signature);

	return ret;
}

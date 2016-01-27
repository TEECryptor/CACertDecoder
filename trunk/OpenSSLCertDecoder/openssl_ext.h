//	File Name: openssl_ext.h

#ifndef _OPENSSL_EXT_H_
#define	_OPENSSL_EXT_H_

#include <crtdefs.h>
#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>

time_t ASN1_TIME_get(ASN1_TIME * a, int *err);

#endif	//_OPENSSL_EXT_H_
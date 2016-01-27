#include "stdafx.h"
#include "OpenSSLCertificate.h"
#include "openssl_ext.h"
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
 
COpenSSLCertificate::COpenSSLCertificate(void)
 : m_pbtCertData(NULL)
 , m_ulCertDataLen(0)
 , m_ulCertType(0)
 , m_pX509(NULL)
{
}

COpenSSLCertificate::~COpenSSLCertificate(void)
{
	if (m_pbtCertData)
	{
		delete []m_pbtCertData;
		m_pbtCertData = NULL;
	}
	if (m_pX509)
	{
		X509_free(m_pX509);
		m_pX509 = NULL;
	}
}

ULONG COpenSSLCertificate::FromBuffer(LPBYTE lpCertData, 
								  ULONG ulDataLen, 
								  ULONG ulCertType, 
								  LPSTR lpscPassword)
{
	int rv = CERT_ERR_OK;

	if (!lpCertData || 0 == ulDataLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (m_pX509) 
	{
		X509_free(m_pX509);
		m_pX509 = NULL;
	}

	OPENSSL_init();
	OpenSSL_add_all_algorithms(); 
	
	if (CERT_TYPE_CER == ulCertType)
	{
		m_pX509 = d2i_X509(NULL, (unsigned char const **)&lpCertData, ulDataLen);
		if (m_pX509 == NULL) 
		{
			return CERT_ERR_FAILED;
		}
	}
	else if (CERT_TYPE_P7B == ulCertType)
	{
		PKCS7* p7 = NULL;
		STACK_OF(X509) *certs = NULL;
		BIO* bio = BIO_new(BIO_s_mem());

		rv = BIO_write(bio, lpCertData, ulDataLen);
		p7 = d2i_PKCS7_bio(bio, NULL);
		BIO_free(bio);

		int i = OBJ_obj2nid(p7->type);
		if(i == NID_pkcs7_signed) 
		{
			certs = p7->d.sign->cert;
		} 
		else if(i == NID_pkcs7_signedAndEnveloped) 
		{
			certs = p7->d.signed_and_enveloped->cert;
		}

		// 只支持单证书的p7b
		m_pX509 = sk_X509_value(certs, 0);
		if (m_pX509 == NULL) 
		{
			return CERT_ERR_FAILED;
		}
	}
	else if (CERT_TYPE_PFX == ulCertType)
	{
		PKCS12 *p12 = NULL;
		EVP_PKEY *pkey = NULL;
		STACK_OF(X509) *ca = NULL;
		BIO *bio; 

		bio = BIO_new(BIO_s_mem());
		rv = BIO_write(bio, lpCertData, ulDataLen);
		p12 = d2i_PKCS12_bio(bio, NULL);
		BIO_free_all(bio); 

		rv = PKCS12_parse(p12, lpscPassword, &pkey, &m_pX509, &ca);
		if (!rv || !m_pX509)
		{
			rv = CERT_ERR_FAILED;
			goto FREE_MEMORY;
		}

FREE_MEMORY:
		PKCS12_free(p12);
		EVP_PKEY_free(pkey);
		sk_X509_free(ca);
	}
	else
	{
		return CERT_ERR_INVALIDPARAM;
	}

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::ToBuffer(LPBYTE lpCertData, 
									ULONG *pulDataLen)
{
	ULONG ulDataLen = 0;
	unsigned char* pData = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulDataLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	ulDataLen = i2d_X509(m_pX509, NULL);

	if (!lpCertData)
	{
		*pulDataLen = ulDataLen;
		return CERT_ERR_OK;
	}
	if (*pulDataLen < ulDataLen)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	ulDataLen = i2d_X509(m_pX509, &pData);
	memcpy_s(lpCertData, *pulDataLen, pData, ulDataLen);
	*pulDataLen = ulDataLen;

	delete []pData;
	pData = NULL;

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_Version(ULONG *pulVer)
{
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulVer)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	*pulVer = X509_get_version(m_pX509);
	*pulVer += 1;	//0 for ver1

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_SN(LPSTR lptcSN,
								  ULONG *pulLen)
{
	ULONG ulRet = CERT_ERR_OK;
    ASN1_INTEGER *asn1_i = NULL;
    BIGNUM *bignum = NULL;
    char *serial = NULL;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

    asn1_i = X509_get_serialNumber(m_pX509);

    bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
    if (bignum == NULL) 
	{
		ulRet = CERT_ERR_FAILED;
		goto FREE_MEMORY;
	}

	serial = BN_bn2hex(bignum);
    if (serial == NULL) 
	{
		ulRet = CERT_ERR_FAILED;
		goto FREE_MEMORY;
	}

    BN_free(bignum);

	if (!lptcSN)
	{
		*pulLen = strlen(serial) + 1;
		ulRet = CERT_ERR_OK;
		goto FREE_MEMORY;
	}
	if (*pulLen < strlen(serial) + 1)
	{
		ulRet = CERT_ERR_BUFFER_TOO_SMALL;
		goto FREE_MEMORY;
	}

    strcpy_s(lptcSN, *pulLen, serial);
	*pulLen = strlen(serial);

FREE_MEMORY:
    OPENSSL_free(serial);
	
	return ulRet;
}

ULONG COpenSSLCertificate::get_SignatureAlgOid(LPSTR lpscOid, ULONG *pulLen)
{
	char oid[128] = {0};
	ASN1_OBJECT* salg  = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	salg = m_pX509->sig_alg->algorithm;
	OBJ_obj2txt(oid, 128, salg, 1);

	if (!lpscOid)
	{
		*pulLen = strlen(oid) + 1;
		return CERT_ERR_OK;
	}
	if (*pulLen < strlen(oid) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	strcpy_s(lpscOid, *pulLen, oid);
	*pulLen = strlen(oid) + 1;

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_KeyType(ULONG* pulType)
{
	EVP_PKEY *pk = NULL;
	stack_st_X509* chain = NULL;
	X509_EXTENSION *pex = NULL;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulType)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	pk = X509_get_pubkey(m_pX509);
	if (!pk)
	{
		return CERT_ERR_FAILED;
	}

	if (EVP_PKEY_RSA == pk->type)
	{
		*pulType = CERT_KEY_ALG_RSA;
	}
	else if (EVP_PKEY_EC == pk->type)
	{
		*pulType = CERT_KEY_ALG_ECC;
	}
	else if (EVP_PKEY_DSA == pk->type)
	{
		*pulType = CERT_KEY_ALG_DSA;
	}
	else if (EVP_PKEY_DH == pk->type)
	{
		*pulType = CERT_KEY_ALG_DH;
	}
	else
	{
		return CERT_KEY_ALG_UNKNOWN;
	}		
	
	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_KeyUsage(ULONG* lpUsage)
{
	ULONG lKeyUsage = 0;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!lpUsage)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	*lpUsage = CERT_USAGE_UNKNOWN;
	
	//	X509_check_ca() MUST be called!
	X509_check_ca(m_pX509);

	lKeyUsage = m_pX509->ex_kusage;
	if ((lKeyUsage & KU_DATA_ENCIPHERMENT) == KU_DATA_ENCIPHERMENT)
	{
		*lpUsage = CERT_USAGE_EXCH;
	}
	else if ((lKeyUsage & KU_DIGITAL_SIGNATURE) == KU_DIGITAL_SIGNATURE)
	{
		*lpUsage = CERT_USAGE_SIGN;
	}

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_ValidDate(SYSTEMTIME *ptmStart, 
										 SYSTEMTIME *ptmEnd)
{
	int err = 0;
	ASN1_TIME *start = NULL;
	ASN1_TIME *end = NULL;
	time_t ttStart = {0};
	time_t ttEnd = {0};
	LONGLONG nLLStart = 0;
	LONGLONG nLLEnd = 0;
	FILETIME ftStart = {0};
	FILETIME ftEnd = {0};

	if (!m_pX509)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	start = X509_get_notBefore(m_pX509);
	end = X509_get_notAfter(m_pX509);
	
	ttStart = ASN1_TIME_get(start, &err);
	ttEnd = ASN1_TIME_get(end, &err);
	
    nLLStart = Int32x32To64(ttStart, 10000000) + 116444736000000000;
    nLLEnd = Int32x32To64(ttEnd, 10000000) + 116444736000000000;

    ftStart.dwLowDateTime = (DWORD)nLLStart;
    ftStart.dwHighDateTime = (DWORD)(nLLStart >> 32);

    ftEnd.dwLowDateTime = (DWORD)nLLEnd;
    ftEnd.dwHighDateTime = (DWORD)(nLLEnd >> 32);

    FileTimeToSystemTime(&ftStart, ptmStart);
    FileTimeToSystemTime(&ftEnd, ptmEnd);

	return 0;
}

ULONG COpenSSLCertificate::get_Issuer(LPSTR lpValue, 
									  ULONG *pulLen)
{
	int nNameLen = 512;
	CHAR csCommonName[512] = {0};
	X509_NAME *pCommonName = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	pCommonName = X509_get_issuer_name(m_pX509);
	if (!pCommonName)
	{
		return CERT_ERR_FAILED;
	}

	nNameLen = X509_NAME_get_text_by_NID(pCommonName, NID_commonName, csCommonName, nNameLen);
	if (-1 == nNameLen)
	{
		return CERT_ERR_FAILED;
	};
	
	if (!lpValue)
	{
		*pulLen = nNameLen + 1;
		return CERT_ERR_OK;
	}
	if (*pulLen < (ULONG)nNameLen + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	strcpy_s(lpValue, *pulLen, csCommonName);
	*pulLen = nNameLen;

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_SubjectName(LPSTR lpValue, 
										   ULONG *pulLen)
{
	int iLen = 0;
	int iSubNameLen = 0;
	CHAR csSubName[1024] = {0};
	CHAR csBuf[256] = {0};
	X509_NAME *pSubName = NULL;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	pSubName = X509_get_subject_name(m_pX509);
	if (!pSubName)
	{
		return CERT_ERR_FAILED;
	}
	
	ZeroMemory(csBuf, 256);
	strcat_s(csSubName, 1024, "C=");
	iLen = X509_NAME_get_text_by_NID(pSubName, NID_countryName, csBuf, 256);
	if (iLen > 0)
	{
		strcat_s(csSubName, 1024, csBuf);
	}
	strcat_s(csSubName, 1024, ", ");
	
	ZeroMemory(csBuf, 256);
	strcat_s(csSubName, 1024, "O=");
	iLen = X509_NAME_get_text_by_NID(pSubName, NID_organizationName, csBuf, 256);
	if (iLen > 0)
	{
		strcat_s(csSubName, 1024, csBuf);
	}
	strcat_s(csSubName, 1024, ", ");
	
	ZeroMemory(csBuf, 256);
	strcat_s(csSubName, 1024, "OU=");
	iLen = X509_NAME_get_text_by_NID(pSubName, NID_organizationalUnitName, csBuf, 256);
	if (iLen > 0)
	{
		strcat_s(csSubName, 1024, csBuf);
	}
	strcat_s(csSubName, 1024, ", ");
	
	ZeroMemory(csBuf, 256);
	strcat_s(csSubName, 1024, "CN=");
	iLen = X509_NAME_get_text_by_NID(pSubName, NID_commonName, csBuf, 256);
	if (iLen > 0)
	{
		strcat_s(csSubName, 1024, csBuf);
	}
	
	if (!lpValue)
	{
		*pulLen = strlen(csSubName) + 1;
		return CERT_ERR_OK;
	}
	if (*pulLen < strlen(csSubName) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	
	strcpy_s(lpValue, *pulLen, csSubName);
	*pulLen = strlen(csSubName);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_PublicKey(LPCERTPUBKEY lpPubKeyBlob)
{
	EVP_PKEY *pk = NULL;
	stack_st_X509* chain = NULL;
	X509_EXTENSION *pex = NULL;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!lpPubKeyBlob)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	pk = X509_get_pubkey(m_pX509);
	if (!pk)
	{
		return CERT_ERR_FAILED;
	}
		
	int len = 0;
	CHAR *pNum = NULL;
	if (EVP_PKEY_RSA == pk->type)
	{
		BYTE e[4] = {0};
		lpPubKeyBlob->ulAlg = CERT_KEY_ALG_RSA;

		len = BN_bn2bin(pk->pkey.rsa->n, lpPubKeyBlob->rsa.btModulus);
		lpPubKeyBlob->rsa.ulBits = 8 * len;

		len = BN_bn2bin(pk->pkey.rsa->e, e);
		lpPubKeyBlob->rsa.btExp[0] = e[3];
		lpPubKeyBlob->rsa.btExp[1] = e[2];
		lpPubKeyBlob->rsa.btExp[2] = e[1];
		lpPubKeyBlob->rsa.btExp[3] = e[0];
	}
	else if (EVP_PKEY_EC == pk->type)
	{
		ULONG ulPKeyLen = 0;
		BYTE btEccPKey[128] = {0};
		LPBYTE lpOut = btEccPKey;
		lpPubKeyBlob->ulAlg = CERT_KEY_ALG_ECC;

		ulPKeyLen = i2o_ECPublicKey(pk->pkey.ec, &lpOut);
		if (ulPKeyLen > 0)
		{
			lpPubKeyBlob->ecc.ulBits = ((ulPKeyLen-1) / 2) * 8;
			memcpy(lpPubKeyBlob->ecc.ulX + 32, btEccPKey + 1, (ulPKeyLen-1) / 2);
			memcpy(lpPubKeyBlob->ecc.ulY + 32, btEccPKey + 1 + (ulPKeyLen-1) / 2, (ulPKeyLen-1) / 2);
		}
	}
	else
	{
		return CERT_ERR_NOTSUPPORT;
	}

	return 0;
}

ULONG COpenSSLCertificate::get_HashAlgID(ULONG *pulHashAlg)
{
	ULONG ulRes = 0;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulHashAlg)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	*pulHashAlg = CERT_HASH_ALG_SHA1;
	
	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_HashValue(LPBYTE lpbtHash, ULONG *pulHashLen)
{
	ULONG ulRes = 0;
	
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulHashLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (!lpbtHash)
	{
		*pulHashLen = 20;
		return CERT_ERR_OK;
	}

	memcpy_s(lpbtHash, *pulHashLen , m_pX509->sha1_hash, 20);
	*pulHashLen = 20;
	
	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_ExtensionCnt(ULONG* pulCount)
{
	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulCount)
	{
		return CERT_ERR_INVALIDPARAM;
	}	

	*pulCount = X509_get_ext_count(m_pX509);
	
	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_ExtensionOid(ULONG ulIndex, 
											LPSTR lpscExtOid, 
											ULONG* pulLen, 
											BOOL *pbIsCrit)
{
	char oid[128] = {0};
	X509_EXTENSION* ext = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulLen || !pbIsCrit)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	ext = X509_get_ext(m_pX509, ulIndex);
	if (!ext)
	{
		return CERT_ERR_FAILED;
	}
	
	*pbIsCrit = (ext->critical == -1) ? FALSE : TRUE;
	OBJ_obj2txt(oid, sizeof(oid), ext->object, 1);
	if (!lpscExtOid)
	{
		*pulLen = strlen(oid) + 1;
		return CERT_ERR_OK;
	}

	if (*pulLen < strlen(oid) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	strcpy_s(lpscExtOid, *pulLen, oid);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::get_ExtensionByOid(LPCSTR lpcsExtOid, 
											  LPSTR lpscExtension, 
											  ULONG* pulLen)
{
	ULONG ulRes = 0;
	int nid = 0;
	ASN1_OBJECT* obj = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!lpcsExtOid || !pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	obj = OBJ_txt2obj(lpcsExtOid, 1);
	if (!obj)
	{
		return CERT_ERR_NOTSUPPORT;
	}

	nid = OBJ_obj2nid(obj);	
	switch(nid)
	{
	case NID_basic_constraints:
		ulRes = _GetExtBasicConstraints(m_pX509, lpscExtension, pulLen);
		break;
	case NID_key_usage:
		ulRes = _GetExtKeyUsage(m_pX509, lpscExtension, pulLen);
		break;
	case NID_ext_key_usage:
		ulRes = _GetExtEnhancedKeyUsage(m_pX509, lpscExtension, pulLen);
		break;		
	case NID_authority_key_identifier:
		ulRes = _GetExtAuthorityIdentifier(m_pX509, lpscExtension, pulLen);
		break;	
	case NID_subject_key_identifier:
		ulRes = _GetExtSubjectIdentifier(m_pX509, lpscExtension, pulLen);
		break;		
	case NID_crl_distribution_points:
		ulRes = _GetExtCRLDistPoints(m_pX509, lpscExtension, pulLen);
		break;		
	case NID_info_access:
		ulRes = _GetExtAuthorityInfoAccess(m_pX509, lpscExtension, pulLen);
		break;	
	case NID_netscape_cert_type:
		ulRes = _GetExtNetscapeCertType(m_pX509, lpscExtension, pulLen);
		break;	
	default:
		ulRes = _GetExtDefault(m_pX509, nid, lpscExtension, pulLen);
		break;
	}	

	return ulRes;
}


ULONG COpenSSLCertificate::_GetExtBasicConstraints(X509 *pX509Cert, 
												   LPSTR lpscProperty, 
												   ULONG* pulLen)
{
	int crit = 0;
	char value[512] = {0};
	BASIC_CONSTRAINTS *bcons = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	bcons = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(m_pX509, NID_basic_constraints, &crit, NULL);
	if (!bcons)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}

	if (!bcons->ca)
	{
		strcat_s(value, 512, "Subject Type=End Entity; ");
		strcat_s(value, 512, "Path Length Constraint=None");
	}
	else
	{
		char temp[128] = {0};
		sprintf_s(temp, 128, "Path Length Constraint=%d", bcons->pathlen);
		strcat_s(value, 512, "Subject Type=CA; ");
		strcat_s(value, 512, temp);
	}
	BASIC_CONSTRAINTS_free(bcons);

	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtKeyUsage(X509 *pX509Cert, 
										   LPSTR lpscProperty, 
										   ULONG* pulLen)
{	
	char value[512] = {0};
	ASN1_BIT_STRING* lASN1UsageStr;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	lASN1UsageStr = (ASN1_BIT_STRING *)X509_get_ext_d2i(m_pX509, NID_key_usage, NULL, NULL);
	if (lASN1UsageStr)
	{
		char temp[32] = {0};
		unsigned short usage = lASN1UsageStr->data[0];
		if(lASN1UsageStr->length > 1)
		{ 
			usage |= lASN1UsageStr->data[1] << 8;
		}
		sprintf_s(temp, 32, "(%x)", usage);

		if (usage & KU_DIGITAL_SIGNATURE)
		{
			strcat_s(value, 512, "Digital Signature, ");
		}
		if (usage & KU_NON_REPUDIATION)
		{
			strcat_s(value, 512, "Non-Repudiation, ");
		}
		if (usage & KU_KEY_ENCIPHERMENT)
		{
			strcat_s(value, 512, "Key Encipherment, ");
		}
		if (usage & KU_DATA_ENCIPHERMENT)
		{
			strcat_s(value, 512, "Data  Encipherment, ");
		}
		if (usage & KU_KEY_AGREEMENT)
		{
			strcat_s(value, 512, "Key  Agreement, ");
		}
		if (usage & KU_KEY_CERT_SIGN)
		{
			strcat_s(value, 512, "Certificate Signature, ");
		}
		if (usage & KU_CRL_SIGN)
		{
			strcat_s(value, 512, "CRL Signature, ");
		}
			
		strcat_s(value, 512, temp);
	}
	else
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtEnhancedKeyUsage(X509 *pX509Cert, 
												   LPSTR lpscProperty, 
												   ULONG* pulLen)
{
	int i = 0;
	char value[512] = {0};
	EXTENDED_KEY_USAGE* extusage;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	extusage = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i(m_pX509, NID_ext_key_usage, NULL, NULL);
	if (!extusage)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	long id[] = {OBJ_email_protect};

	for (i = 0; i < sk_ASN1_OBJECT_num(extusage); i++)
	{
		int j = 0;
		char obj_id[128] = {0};
		char obj_name[128] = {0};
		ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(extusage, i);

		OBJ_obj2txt(obj_id, sizeof(obj_id), obj, 1);
		OBJ_obj2txt(obj_name, sizeof(obj_name), obj, 0);

		if (strlen(value) > 0)
		{
			strcat_s(value, 512, "; ");
		}
		strcat_s(value, 512, obj_name);
		strcat_s(value, 512, " (");
		strcat_s(value, 512, obj_id);
		strcat_s(value, 512, ")");		
	}
    sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
	
	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtAuthorityIdentifier(X509 *pX509Cert, 
													  LPSTR lpscProperty, 
													  ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char value[512] = {0};
	AUTHORITY_KEYID *akeyid = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	akeyid = (AUTHORITY_KEYID*)X509_get_ext_d2i(m_pX509, NID_authority_key_identifier, &crit, NULL);
	if (!akeyid)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	strcat_s(value, 512, "KeyID=");
	for (i = 0; i < akeyid->keyid->length; i++)
	{
		char keyid[8] = {0};
		sprintf_s(keyid, 8, "%x ", akeyid->keyid->data[i]);
		strcat_s(value, 512, keyid);
	}
	
	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtSubjectIdentifier(X509 *pX509Cert, 
													LPSTR lpscProperty, 
													ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char value[512] = {0};
	ASN1_OCTET_STRING *skid = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	skid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(m_pX509, NID_subject_key_identifier, &crit, NULL);
	if (!skid)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	for (i = 0; i < skid->length; i++)
	{
		char keyid[8] = {0};
		sprintf_s(keyid, 8, "%x ", skid->data[i]);
		strcat_s(value, 512, keyid);
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtCRLDistPoints(X509 *pX509Cert, 
												LPSTR lpscProperty, 
												ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char value[512] = {0};
	CRL_DIST_POINTS *crlpoints = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	crlpoints = (CRL_DIST_POINTS*)X509_get_ext_d2i(m_pX509, NID_crl_distribution_points, &crit, NULL);
	if (!crlpoints)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}

	for (i = 0; i < sk_DIST_POINT_num(crlpoints); i++)
	{
		int j, gtype;
		GENERAL_NAMES *gens;
		GENERAL_NAME *gen;
		ASN1_STRING *uri;
		DIST_POINT *dp = sk_DIST_POINT_value(crlpoints, i);		
		if (!dp->distpoint || dp->distpoint->type != 0)
			continue;
		
		gens = dp->distpoint->name.fullname;
		for (j = 0; j < sk_GENERAL_NAME_num(gens); j++) 
		{
			gen = sk_GENERAL_NAME_value(gens, j);
			uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);
			if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) 
			{
				char *uptr = (char *)ASN1_STRING_data(uri);
				if (strlen(value) > 0)
				{
					strcat_s(value, 512, " | ");
				}
				strcat_s(value, 512, uptr);
			}
		}
	}
	CRL_DIST_POINTS_free(crlpoints);
	
	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtAuthorityInfoAccess(X509 *pX509Cert, 
													  LPSTR lpscProperty, 
													  ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char value[512] = {0};
	AUTHORITY_INFO_ACCESS *accinfo = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	accinfo = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(m_pX509, NID_info_access, &crit, NULL);
	if (!accinfo)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}	
	
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(accinfo); i++) 
	{
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(accinfo, i);
        if (ad && ad->location && ad->location->type == GEN_URI) 
		{
			char temp[256] = {0};
			char method[32] = {0};

			char *uptr = (char *)ASN1_STRING_data(ad->location->d.uniformResourceIdentifier);
			if (strlen(value) > 0)
			{
				strcat_s(value, 512, " | ");
			}
			OBJ_obj2txt(method, 32, ad->method, 1);
			sprintf_s(temp, 256, "Access Method=证书颁发机构颁发者 (%s), \r\n", method);
			strcat_s(value, 512, temp);
			strcat_s(value, 512, uptr);
		}
    }
    AUTHORITY_INFO_ACCESS_free(accinfo);
	
	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtNetscapeCertType(X509 *pX509Cert, 
												   LPSTR lpscProperty, 
												   ULONG* pulLen)
{
	int i = 0;
	int crit = 0;
	char temp[8] = {0};
	char value[512] = {0};
	ASN1_OCTET_STRING *ns = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	ns = (ASN1_OCTET_STRING*)X509_get_ext_d2i(m_pX509, NID_netscape_cert_type, &crit, NULL);
	if (!ns)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	if (ns->length > 0)
	{
		if (ns->data[0] & NS_SSL_CLIENT)
		{
			strcat_s(value, 512, "SSL 客户端身份验证; ");
		}
		if (ns->data[0] & NS_SSL_SERVER)
		{
			strcat_s(value, 512, "SSL 服务器端身份验证; ");
		}
		if (ns->data[0] & NS_SMIME)
		{
			strcat_s(value, 512, "SMIME; ");
		}
		if (ns->data[0] & NS_OBJSIGN)
		{
			strcat_s(value, 512, "签名; ");
		}
		if (ns->data[0] & NS_SSL_CA)
		{
			strcat_s(value, 512, "SSL CA; ");
		}
		if (ns->data[0] & NS_SMIME_CA)
		{			
			strcat_s(value, 512, "SMIME CA; ");
		}
		if (ns->data[0] & NS_OBJSIGN_CA)
		{
			strcat_s(value, 512, "Sign CA; ");
		}
		if (ns->data[0] & NS_ANY_CA)
		{
			strcat_s(value, 512, "任何类型; ");
		}
		sprintf_s(temp, 8, "(%x)", ns->data[0]);
	}
	else
	{
		sprintf_s(temp, 8, "(%x)", 0);
	}			
	strcat_s(value, 512, temp);

	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);
		
	return CERT_ERR_OK;
}

ULONG COpenSSLCertificate::_GetExtDefault(X509 *pX509Cert,
										  ULONG ulNID,
										  LPSTR lpscProperty, 
										  ULONG* pulLen)
{	
	int i = 0;
	int crit = 0;
	char value[512] = {0};
	ASN1_OCTET_STRING *id = NULL;

	if (!m_pX509)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	id = (ASN1_OCTET_STRING*)X509_get_ext_d2i(m_pX509, ulNID, &crit, NULL);
	if (!id)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	for (i = 0; i < id->length; i++)
	{
		char keyid[8] = {0};
		sprintf_s(keyid, 8, "%x ", id->data[i]);
		strcat_s(value, 512, keyid);
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(value) + 1;
	}
	if (*pulLen < (strlen(value) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, value);

	return CERT_ERR_OK;
}
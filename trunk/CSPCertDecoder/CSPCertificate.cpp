/***************************************************
 *	File Name:CSPCertificate.h
 *	Author:yyfzy(QQ:41707352)
 *	Date:2015/04/03
 *	Introduce:This source file is CSP Certificate class implement file
 */

#include "stdafx.h"
#include "CSPCertificate.h"
#include <atlconv.h>

#define GLOBAL_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

CCSPCertificate::CCSPCertificate(void)
 : m_pCertContext(NULL)
{
}

CCSPCertificate::~CCSPCertificate(void)
{
	if (m_pCertContext)
	{
		CertFreeCertificateContext(m_pCertContext);
		m_pCertContext = NULL;
	}
}

ULONG CCSPCertificate::FromBuffer(LPBYTE lpCertData, 
								  ULONG ulDataLen, 
								  ULONG ulCertType, 
								  LPSTR lpscPassword)
{
	if (!lpCertData || ulDataLen == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (CERT_TYPE_CER == ulCertType)
	{
		return _DecodeX509Cert(lpCertData, ulDataLen);
	}
	else if (CERT_TYPE_P7B == ulCertType)
	{
		return _DecodeP7bCert(lpCertData, ulDataLen);
	}
	else if (CERT_TYPE_PFX == ulCertType)
	{
		return _DecodePfxCert(lpCertData, ulDataLen, lpscPassword);
	}
	else
	{
		return CERT_ERR_INVALIDPARAM;
	}
		
	return CERT_ERR_OK;
}

ULONG CCSPCertificate::ToBuffer(LPBYTE lpCertData, 
								ULONG *pulDataLen)
{
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulDataLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (!lpCertData)
	{
		*pulDataLen = m_pCertContext->cbCertEncoded;
		return CERT_ERR_OK;
	}

	if (*pulDataLen < m_pCertContext->cbCertEncoded)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	memcpy(lpCertData, m_pCertContext->pbCertEncoded, m_pCertContext->cbCertEncoded);
	*pulDataLen = m_pCertContext->cbCertEncoded;

	return CERT_ERR_OK;
}


ULONG CCSPCertificate::get_Version(ULONG *pulVer)
{	
	DWORD dwVer = 0;
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulVer)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	dwVer = m_pCertContext->pCertInfo->dwVersion;
	switch(dwVer)
	{
	case CERT_V1:
		*pulVer = 1;
		break;
	case CERT_V2:
		*pulVer = 2;
		break;
	case CERT_V3:
		*pulVer = 3;
		break;
	}

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_SN(LPSTR lptcSN,
							  ULONG *pulLen)
{	
	CHAR scSN[512] = {0};

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	PCRYPT_INTEGER_BLOB pSn = &(m_pCertContext->pCertInfo->SerialNumber);
	for (int n = (int)(pSn->cbData - 1); n >= 0; n--)
	{
		CHAR szHex[5] = {0};
		sprintf_s(szHex, "%02X", (pSn->pbData)[n]);
		strcat_s(scSN, 512, szHex);
	}

	if (!lptcSN)
	{
		*pulLen = strlen(scSN) + 1;
		return CERT_ERR_OK;
	}

	if (*pulLen <= strlen(scSN) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lptcSN, *pulLen, scSN);
	*pulLen = strlen(scSN);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_KeyType(ULONG* pulType)
{	
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulType)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	PCERT_PUBLIC_KEY_INFO pPubKey = &(m_pCertContext->pCertInfo->SubjectPublicKeyInfo);
	if (pPubKey)
	{
		if (_stricmp(pPubKey->Algorithm.pszObjId, szOID_RSA_RSA) == 0)
		{
			*pulType = CERT_KEY_ALG_RSA;
		}
		else if (_stricmp(pPubKey->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0)
		{
			*pulType = CERT_KEY_ALG_ECC;
		}
		else 
		{
			*pulType = 0;
			return CERT_ERR_ALG_UNKNOWN;
		}
	}
	else
	{
		return GetLastError();
	}

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_KeyUsage(ULONG* lpUsage)
{	
	BYTE btUsage[2] = {0};

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!lpUsage)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (CertGetIntendedKeyUsage(GLOBAL_ENCODING_TYPE, m_pCertContext->pCertInfo, btUsage, 2))
	{
		if (btUsage[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE)
		{
			*lpUsage = CERT_USAGE_SIGN;
		}
		else if (btUsage[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE)
		{
			*lpUsage = CERT_USAGE_EXCH;
		}
		else
		{
			*lpUsage = 0;
			return CERT_ERR_USAGE_UNKNOWN;
		}
	}
	else
	{
		return GetLastError();
	}

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_SignatureAlgOid(LPSTR lpscOid, 
										   ULONG *pulLen)
{
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlg = &(m_pCertContext->pCertInfo->SignatureAlgorithm);
	if (!pSignatureAlg)
	{
		return GetLastError();
	}

	if (!lpscOid)
	{
		*pulLen = strlen(pSignatureAlg->pszObjId) + 1;
		return CERT_ERR_OK;
	}
	if (*pulLen < strlen(pSignatureAlg->pszObjId) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	strcpy_s(lpscOid, *pulLen, pSignatureAlg->pszObjId);
	*pulLen = strlen(pSignatureAlg->pszObjId) + 1;

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_ValidDate(SYSTEMTIME *ptmStart, 
									 SYSTEMTIME *ptmEnd)
{
	FILETIME ftStart;
	FILETIME ftEnd;

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (ptmStart)
	{
		memcpy(&ftStart, &m_pCertContext->pCertInfo->NotBefore, sizeof(FILETIME));
		FileTimeToSystemTime(&ftStart, ptmStart);
	}
	if (ptmEnd)
	{
		memcpy(&ftEnd, &m_pCertContext->pCertInfo->NotAfter, sizeof(FILETIME));
		FileTimeToSystemTime(&ftEnd, ptmEnd);
	}

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_Issuer(LPSTR lpValue, ULONG *pulLen)
{
	ULONG hr = CERT_ERR_OK;
	ULONG ulIssuerLen = 0;
	LPTSTR lpszIssuer = NULL;
	
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	hr = _GetPropertyValue(szOID_COMMON_NAME, CERT_NAME_ISSUER_FLAG, NULL, ulIssuerLen);
	if (0 != hr || ulIssuerLen == 0)
	{
		return hr;
	}

	if (!lpValue)
	{
		*pulLen = ulIssuerLen;
		return CERT_ERR_OK;
	}
	if (*pulLen <ulIssuerLen)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	
	hr = _GetPropertyValue(szOID_COMMON_NAME, CERT_NAME_ISSUER_FLAG, lpValue, *pulLen);
	if (0 != hr)
	{
		return hr;
	}

	return hr;
}

ULONG CCSPCertificate::get_SubjectName(LPSTR lpValue, 
									   ULONG *pulLen)
{	
	DWORD dwSubjectLen = 0;
	CERT_NAME_BLOB certSubject;

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	certSubject = m_pCertContext->pCertInfo->Subject;
	dwSubjectLen = CertNameToStr(GLOBAL_ENCODING_TYPE, &certSubject, CERT_X500_NAME_STR, NULL, 0);
	if (dwSubjectLen <= 1)
	{
		return E_FAIL;
	}

	if (!lpValue)
	{
		*pulLen = dwSubjectLen;
		return CERT_ERR_OK;
	}
	if (*pulLen < dwSubjectLen)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	*pulLen = CertNameToStrA(GLOBAL_ENCODING_TYPE, &certSubject, CERT_X500_NAME_STR, lpValue, *pulLen);
	if (*pulLen <= 1)
	{
		return GetLastError();
	}

	return CERT_ERR_OK;
}


ULONG CCSPCertificate::get_PublicKey(LPCERTPUBKEY lpPubKeyBlob)
{
	BOOL bResult = TRUE;
	ULONG ulRes = 0;
	ULONG ulKeyAlg = 0;
	ULONG ulKeySpec = 0;
	CERT_PUBLIC_KEY_INFO certPubKeyInfo = {0};
	
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!lpPubKeyBlob)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	ulRes = get_KeyType(&ulKeyAlg);
	if (CERT_ERR_OK != ulRes)
	{
		return ulRes;
	}

	certPubKeyInfo = m_pCertContext->pCertInfo->SubjectPublicKeyInfo;

	if (CERT_KEY_ALG_ECC == ulKeyAlg)
	{
		if (certPubKeyInfo.PublicKey.cbData != (1 + 32 + 32))
		{
			return CERT_ERR_CERTDATA_ERR;
		}

		lpPubKeyBlob->ulAlg = CERT_KEY_ALG_ECC;
		lpPubKeyBlob->ecc.ulBits = 256;
		memcpy(lpPubKeyBlob->ecc.ulX + 32, certPubKeyInfo.PublicKey.pbData + 1, 32);
		memcpy(lpPubKeyBlob->ecc.ulY + 32, certPubKeyInfo.PublicKey.pbData + 1 + 32, 32);
	}
	else
	{		
		HCRYPTPROV hTmpProv = NULL;
		HCRYPTKEY hKey = NULL;
		ULONG ulPubKeyLen = 0;
		LPBYTE lpPubKey = NULL;

		if (!CryptAcquireContextW(&hTmpProv, L"Temp_X509_Container", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			if (!CryptAcquireContextW(&hTmpProv, L"Temp_X509_Container", MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
			{
				ulRes = GetLastError();
				goto FREE_MEMORY;
			}
		}

		if (!CryptImportPublicKeyInfo(hTmpProv, GLOBAL_ENCODING_TYPE, &certPubKeyInfo, &hKey))
		{
			ulRes = GetLastError();
			goto FREE_MEMORY;
		}

		if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &ulPubKeyLen))
		{
			ulRes = GetLastError();
			goto FREE_MEMORY;
		}
		lpPubKey = new BYTE[ulPubKeyLen];
		memset(lpPubKey, 0, ulPubKeyLen);
		if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, lpPubKey, &ulPubKeyLen))
		{
			ulRes = GetLastError();
			goto FREE_MEMORY;
		}
		
		LPBYTE p = lpPubKey + sizeof(PUBLICKEYSTRUC);
		lpPubKeyBlob->ulAlg = CERT_KEY_ALG_RSA;
		lpPubKeyBlob->rsa.ulBits = ((RSAPUBKEY*) p)->bitlen;
		lpPubKeyBlob->rsa.btExp[3] = ((RSAPUBKEY*) p)->pubexp&0x000000FF;
		lpPubKeyBlob->rsa.btExp[2] = (((RSAPUBKEY*) p)->pubexp>>8)&0x000000FF;
		lpPubKeyBlob->rsa.btExp[1] = (((RSAPUBKEY*) p)->pubexp>>16)&0x000000FF;
		lpPubKeyBlob->rsa.btExp[0] = (((RSAPUBKEY*) p)->pubexp>>24)&0x000000FF;
		p += sizeof(RSAPUBKEY);

		switch(lpPubKeyBlob->rsa.ulWrapType)
		{
		case RSA_PUBKEY_WRAPPED_P11:
			for (ULONG ulIndex = 0; ulIndex < lpPubKeyBlob->rsa.ulBits/8; ulIndex++)
			{
				lpPubKeyBlob->rsa.btModulus[ulIndex] = p[lpPubKeyBlob->rsa.ulBits/8-ulIndex-1];
			}
			break;
		case RSA_PUBKEY_WRAPPED_GM:
			for (ULONG ulIndex = 0; ulIndex < lpPubKeyBlob->rsa.ulBits/8; ulIndex++)
			{
				lpPubKeyBlob->rsa.btModulus[(2048/8-lpPubKeyBlob->rsa.ulBits/8)+ulIndex] = p[lpPubKeyBlob->rsa.ulBits/8-ulIndex-1];
			}
			break;
		case RSA_PUBKEY_WRAPPED_CSP:
		default:
			lpPubKeyBlob->rsa.ulWrapType = RSA_PUBKEY_WRAPPED_CSP;
			memcpy(lpPubKeyBlob->rsa.btModulus, p, lpPubKeyBlob->rsa.ulBits/8);
			break;
		}
FREE_MEMORY:	
		if (lpPubKey)
		{
			delete []lpPubKey;
			lpPubKey = NULL;
		}
		if (hKey)
		{
			CryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hTmpProv)
		{
			CryptReleaseContext(hTmpProv, 0);
		}
	}

	return ulRes;
}
	
ULONG CCSPCertificate::get_HashAlgID(ULONG *pulHashAlg)
{
	ULONG ulLen = 128;
	BYTE btData[128] = {0};

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulHashAlg)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	if (!CertGetCertificateContextProperty(m_pCertContext, CERT_SIGN_HASH_CNG_ALG_PROP_ID, btData, &ulLen) || 0 == ulLen)
	{
		*pulHashAlg = CERT_HASH_ALG_SHA1;
	}
	else
	{
		LPCWCHAR lpwcSignHashAlg = (LPCWCHAR)btData;
		if (wcsstr(lpwcSignHashAlg, BCRYPT_MD5_ALGORITHM))
		{
			*pulHashAlg = CERT_HASH_ALG_MD5;
		}
		else if (wcsstr(lpwcSignHashAlg, BCRYPT_SHA1_ALGORITHM))
		{
			*pulHashAlg = CERT_HASH_ALG_SHA1;
		}
		else if (wcsstr(lpwcSignHashAlg, BCRYPT_SHA256_ALGORITHM))
		{
			*pulHashAlg = CERT_HASH_ALG_SHA256;
		}
		else if (wcsstr(lpwcSignHashAlg, BCRYPT_SHA384_ALGORITHM))
		{
			*pulHashAlg = CERT_HASH_ALG_SHA384;
		}
		else if (wcsstr(lpwcSignHashAlg, BCRYPT_SHA512_ALGORITHM))
		{
			*pulHashAlg = CERT_HASH_ALG_SHA512;
		}
		else
		{
			*pulHashAlg = CERT_HASH_ALG_UNKNOWN;
		}
	}

	return CERT_ERR_OK;
}
	
ULONG CCSPCertificate::get_HashValue(LPBYTE lpbtHash, ULONG *pulHashLen)
{
	ULONG ulRes = 0;
	ULONG ulHashAlg = 0;

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulHashLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	get_HashAlgID(&ulHashAlg);
	switch(ulHashAlg)
	{
	case CERT_HASH_ALG_MD5:
		CertGetCertificateContextProperty(m_pCertContext, CERT_MD5_HASH_PROP_ID, lpbtHash, pulHashLen);
		break;
	case CERT_HASH_ALG_SHA1:
		CertGetCertificateContextProperty(m_pCertContext, CERT_SHA1_HASH_PROP_ID, lpbtHash, pulHashLen);
		break;
	default:
		break;
	}

	if (*pulHashLen == 0)
	{
		ulRes = GetLastError();
	}
	else
	{
		ulRes = CERT_ERR_OK;
	}
	
	return ulRes;
}

ULONG CCSPCertificate::get_ExtensionCnt(ULONG* pulCount)
{
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!pulCount)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	*pulCount =	m_pCertContext->pCertInfo->cExtension;

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_ExtensionOid(ULONG ulIndex, 
										LPSTR lpscExtOid, 
										ULONG* pulLen, 
										BOOL *pbIsCrit)
{
	PCERT_EXTENSION pCertExt = NULL;
	
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!lpscExtOid || !pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	if (ulIndex >= m_pCertContext->pCertInfo->cExtension)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	pCertExt = &m_pCertContext->pCertInfo->rgExtension[ulIndex];
	if (!pCertExt)
	{
		return CERT_ERR_FAILED;
	}

	*pbIsCrit = pCertExt->fCritical;
	if (!lpscExtOid)
	{
		*pulLen = strlen(pCertExt->pszObjId) + 1;
		return CERT_ERR_OK;
	}
	if (*pulLen < strlen(pCertExt->pszObjId) + 1)
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}

	strcpy_s(lpscExtOid, *pulLen, pCertExt->pszObjId);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::get_ExtensionByOid(LPCSTR lpcsExtOid, 
										  LPSTR lpscExtension, 
										  ULONG* pulLen)
{
	ULONG ulRes = 0;

	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}

	if (!lpcsExtOid || !pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	if (_stricmp(lpcsExtOid, szOID_BASIC_CONSTRAINTS2) == 0)
	{
		ulRes = _GetExtBasicConstraints(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_KEY_USAGE) == 0)
	{
		ulRes = _GetExtKeyUsage(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_ENHANCED_KEY_USAGE) == 0)
	{
		ulRes = _GetExtEnhancedKeyUsage(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_AUTHORITY_KEY_IDENTIFIER2) == 0)
	{
		ulRes = _GetExtAuthorityIdentifier(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_SUBJECT_KEY_IDENTIFIER) == 0)
	{
		ulRes = _GetExtSubjectIdentifier(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_CRL_DIST_POINTS) == 0)
	{
		ulRes = _GetExtCRLDistPoints(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_AUTHORITY_INFO_ACCESS) == 0)
	{
		ulRes = _GetExtAuthorityInfoAccess(m_pCertContext, lpscExtension, pulLen);
	}
	else if (_stricmp(lpcsExtOid, szOID_NETSCAPE_CERT_TYPE) == 0)
	{
		ulRes = _GetExtNetscapeCertType(m_pCertContext, lpscExtension, pulLen);
	}
	else
	{
		ulRes = _GetExtDefault(m_pCertContext, lpcsExtOid, lpscExtension, pulLen);
	}

	return ulRes;
}

ULONG CCSPCertificate::_DecodeX509Cert(LPBYTE lpCertData, 
									   ULONG ulDataLen)
{	if (!lpCertData || ulDataLen == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}
		
	m_pCertContext = CertCreateCertificateContext(GLOBAL_ENCODING_TYPE, lpCertData, ulDataLen);
	if (!m_pCertContext)
	{
		return GetLastError();
	}
			
	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_DecodeP7bCert(LPBYTE lpCertData, 
									  ULONG ulDataLen)
{
	ULONG ulRes = CERT_ERR_OK;
	ULONG ulFlag = CRYPT_FIRST;
	ULONG ulContainerNameLen = 512;
	CHAR csContainerName[512] = {0};
	BOOL bFoundContainer = FALSE;
	
	if (!lpCertData || ulDataLen == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	HCERTSTORE hCertStore = NULL;
	CRYPT_DATA_BLOB dataBlob = {ulDataLen, lpCertData};
	hCertStore = CertOpenStore(CERT_STORE_PROV_PKCS7, GLOBAL_ENCODING_TYPE, NULL, 0, &dataBlob);
	if (NULL == hCertStore)
	{
		ulRes = GetLastError();
		return ulRes;
	}
	
	if (m_pCertContext)
	{
		CertFreeCertificateContext(m_pCertContext);
		m_pCertContext = NULL;
	}

	m_pCertContext = CertEnumCertificatesInStore(hCertStore, m_pCertContext);
	if (NULL == m_pCertContext)
	{
		ulRes = GetLastError();
		goto CLOSE_STORE;
	}			
	
CLOSE_STORE:
	if (hCertStore)
	{
		CertCloseStore(hCertStore, 0);
		hCertStore = NULL;
	}

	return ulRes;
}

ULONG CCSPCertificate::_DecodePfxCert(LPBYTE lpCertData, 
									  ULONG ulDataLen, 
									  LPSTR lpscPassword)
{
	ULONG ulRes = 0;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT  pCertContext = NULL;  
	
	USES_CONVERSION;

	if (!lpCertData || ulDataLen == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}
		
	// 创建证书库
	CRYPT_DATA_BLOB dataBlob = {ulDataLen, lpCertData};
	hCertStore = PFXImportCertStore(&dataBlob, lpscPassword ? A2W(lpscPassword) : NULL, CRYPT_EXPORTABLE);
	if (NULL == hCertStore)
	{
		hCertStore = PFXImportCertStore(&dataBlob, L"", CRYPT_EXPORTABLE);
	}
	if (NULL == hCertStore)
	{
		ulRes = GetLastError();
		return ulRes;
	}
		
	// 枚举证书，只处理第一个证书
	while(pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
	{		
		if (pCertContext->pbCertEncoded && pCertContext->cbCertEncoded > 0)
		{
			m_pCertContext = CertDuplicateCertificateContext(pCertContext);
			break;
		}
	}
	
	CertCloseStore(hCertStore, 0);
	hCertStore = NULL;

	return ulRes;
}

ULONG CCSPCertificate::_GetPropertyValue(LPCSTR szOId, 
										 DWORD dwSourceId, 
										 LPSTR lpValue, 
										 DWORD &dwValLen)
{
	if (!m_pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	
	dwValLen = CertGetNameStringA(m_pCertContext, CERT_NAME_ATTR_TYPE, 
		dwSourceId == CERT_NAME_ISSUER_FLAG ? 1 : 0, (void*)szOId, NULL, 0);
	if (dwValLen <= 1)
	{
		return GetLastError();
	}

	if (!lpValue)
	{
		return CERT_ERR_OK;
	}

	dwValLen = CertGetNameStringA(m_pCertContext, CERT_NAME_ATTR_TYPE, 
		dwSourceId == CERT_NAME_ISSUER_FLAG ? 1 : 0, (void*)szOId, lpValue, dwValLen);
	if (dwValLen <= 1)
	{
		return GetLastError();
	}

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtBasicConstraints(PCCERT_CONTEXT pCertContext, 
											   LPSTR lpscProperty, 
											   ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_BASIC_CONSTRAINTS2, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (pCertExt)
	{
		PCERT_BASIC_CONSTRAINTS2_INFO pInfo = (PCERT_BASIC_CONSTRAINTS2_INFO)btData;
		if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_BASIC_CONSTRAINTS2, 
								pCertExt->Value.pbData, pCertExt->Value.cbData, 
								CRYPT_DECODE_NOCOPY_FLAG, pInfo, &ulDataLen))
		{
			if (pInfo->fCA) 
			{
				strcat_s(csProperty, 512, "Subject Type=CA; ");
			}
			else 
			{
				strcat_s(csProperty, 512, "Subject Type=End Entity; ");
			}
			if (pInfo->fPathLenConstraint) 
			{
				CHAR csTemp[128] = {0};
				sprintf_s(csTemp, 128, "Path Length Constraint=%d", pInfo->dwPathLenConstraint);
				strcat_s(csProperty, 512, csTemp);
			}
			else
			{
				strcat_s(csProperty, 512, "Path Length Constraint=None");
			}
		}
		else
		{
			return GetLastError();
		}		
	}
	else
	{
		pCertExt = CertFindExtension(szOID_BASIC_CONSTRAINTS, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 		
		if (pCertExt)
		{
			PCERT_BASIC_CONSTRAINTS_INFO pInfo = (PCERT_BASIC_CONSTRAINTS_INFO)btData;
			if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_BASIC_CONSTRAINTS, 
									pCertExt->Value.pbData, pCertExt->Value.cbData, 
									CRYPT_DECODE_NOCOPY_FLAG, pInfo, &ulDataLen))
			{
				if (pInfo->SubjectType.pbData[0] & CERT_CA_SUBJECT_FLAG) 
				{
					strcat_s(csProperty, 512, "Subject Type=CA; ");
				}
				else if (pInfo->SubjectType.pbData[0] & CERT_END_ENTITY_SUBJECT_FLAG) 
				{
					strcat_s(csProperty, 512, "Subject Type=End Entity; ");
				}
				else
				{
					strcat_s(csProperty, 512, "Subject Type=Unknown; ");
				}
				if (pInfo->fPathLenConstraint) 
				{
					CHAR csTemp[128] = {0};
					sprintf_s(csTemp, 128, "Path Length Constraint=%d", pInfo->dwPathLenConstraint);
					strcat_s(csProperty, 512, csTemp);
				}
				else
				{
					strcat_s(csProperty, 512, "Path Length Constraint=None");
				}
			}
			else
			{
				return GetLastError();
			}	
		}
		else
		{
			return CERT_ERR_ATTR_NOTEXIST;
		}	
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtKeyUsage(PCCERT_CONTEXT pCertContext, 
									   LPSTR lpscProperty, 
									   ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_KEY_USAGE, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}

	PCRYPT_BIT_BLOB pBlob = (PCRYPT_BIT_BLOB)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_KEY_USAGE, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pBlob, &ulDataLen))
	{
		USHORT nValue = 0;
		CHAR csValue[32] = {0};
		if (pBlob->cbData == 1) nValue = pBlob->pbData[0];
		else nValue = pBlob->pbData[0] | (pBlob->pbData[1] << 8);
		sprintf_s(csValue, 32, "(%x)", nValue);
		if (pBlob->pbData[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Digital Signature, ");
		}
		if (pBlob->pbData[0] & CERT_NON_REPUDIATION_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Non-Repudiation, ");
		}
		if (pBlob->pbData[0] & CERT_KEY_ENCIPHERMENT_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Key Encipherment, ");
		}
		if (pBlob->pbData[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Data  Encipherment, ");
		}
		if (pBlob->pbData[0] & CERT_KEY_AGREEMENT_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Key  Agreement, ");
		}
		if (pBlob->pbData[0] & CERT_KEY_CERT_SIGN_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Certificate Signature, ");
		}
		if (pBlob->pbData[0] & CERT_OFFLINE_CRL_SIGN_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Offline CRL Signature, ");
		}
		if (pBlob->pbData[0] & CERT_CRL_SIGN_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "CRL Signature, ");
		}
		if (pBlob->pbData[0] & CERT_ENCIPHER_ONLY_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Only encypt data, ");
		}
		if (pBlob->pbData[1] & CERT_DECIPHER_ONLY_KEY_USAGE)
		{
			strcat_s(csProperty, 512, "Only decypt data, ");
		}
			
		strcat_s(csProperty, 512, csValue);
	}
	else
	{
		return GetLastError();
	}
	
	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtEnhancedKeyUsage(PCCERT_CONTEXT pCertContext, 
											   LPSTR lpscProperty, 
											   ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_ENHANCED_KEY_USAGE, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
		
	PCERT_ENHKEY_USAGE pEnhanceUsage = (PCERT_ENHKEY_USAGE)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_ENHANCED_KEY_USAGE, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pEnhanceUsage, &ulDataLen))
	{
		for (ULONG ulIndex = 0; ulIndex < pEnhanceUsage->cUsageIdentifier; ulIndex++)
		{
			
			if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_SERVER_AUTH) == 0)
			{
				strcat_s(csProperty, 512, "服务器认证 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_SERVER_AUTH);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_CLIENT_AUTH) == 0)
			{
				strcat_s(csProperty, 512, "客户端认证 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_CLIENT_AUTH);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_CODE_SIGNING) == 0)
			{
				strcat_s(csProperty, 512, "程序代码签名 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_CODE_SIGNING);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_EMAIL_PROTECTION) == 0)
			{
				strcat_s(csProperty, 512, "安全电子邮件 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_EMAIL_PROTECTION);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_IPSEC_END_SYSTEM) == 0)
			{
				strcat_s(csProperty, 512, "IP终端系统安全 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_IPSEC_END_SYSTEM);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_IPSEC_TUNNEL) == 0)
			{
				strcat_s(csProperty, 512, "IP通道安全 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_IPSEC_TUNNEL);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_IPSEC_USER) == 0)
			{
				strcat_s(csProperty, 512, "IP用户安全 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_IPSEC_USER);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_TIMESTAMP_SIGNING) == 0)
			{
				strcat_s(csProperty, 512, "时间戳签名 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_TIMESTAMP_SIGNING);
				strcat_s(csProperty, 512, "); ");
			}
			else if (_stricmp(pEnhanceUsage->rgpszUsageIdentifier[ulIndex], szOID_PKIX_KP_OCSP_SIGNING) == 0)
			{
				strcat_s(csProperty, 512, "OCSP签名 (");
				strcat_s(csProperty, 512, szOID_PKIX_KP_OCSP_SIGNING);
				strcat_s(csProperty, 512, "); ");
			}
			else
			{
				strcat_s(csProperty, 512, "(");
				strcat_s(csProperty, 512, pEnhanceUsage->rgpszUsageIdentifier[ulIndex]);
				strcat_s(csProperty, 512, "); ");
			}
		}
	}
	else
	{
		return GetLastError();
	}		
	
	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtAuthorityIdentifier(PCCERT_CONTEXT pCertContext, 
												  LPSTR lpscProperty, 
												  ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
		
	PCERT_AUTHORITY_KEY_ID2_INFO pAuthorityKeyID2 = (PCERT_AUTHORITY_KEY_ID2_INFO)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_AUTHORITY_KEY_IDENTIFIER2, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pAuthorityKeyID2, &ulDataLen))
	{
		strcat_s(csProperty, 512, "KeyID=");

		for (ULONG ulIndex = 0; ulIndex < pAuthorityKeyID2->KeyId.cbData; ulIndex++)
		{
			CHAR csKeyID[8] = {0};
			sprintf_s(csKeyID, 8, "%x ", pAuthorityKeyID2->KeyId.pbData[ulIndex]);
			strcat_s(csProperty, 512, csKeyID);
		}
	}
	else
	{
		return GetLastError();
	}
	
	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtSubjectIdentifier(PCCERT_CONTEXT pCertContext, 
												LPSTR lpscProperty, 
												ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
			
	PCRYPT_DATA_BLOB pDataBlob = (PCRYPT_DATA_BLOB)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pDataBlob, &ulDataLen))
	{
		for (ULONG ulIndex = 0; ulIndex < pDataBlob->cbData; ulIndex++)
		{
			CHAR csKeyID[8] = {0};
			sprintf_s(csKeyID, 8, "%x ", pDataBlob->pbData[ulIndex]);
			strcat_s(csProperty, 512, csKeyID);
		}
	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtCRLDistPoints(PCCERT_CONTEXT pCertContext, 
											LPSTR lpscProperty, 
											ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	USES_CONVERSION;

	pCertExt = CertFindExtension(szOID_CRL_DIST_POINTS, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
		
	PCRL_DIST_POINTS_INFO pCRLDistPoint = (PCRL_DIST_POINTS_INFO)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_CRL_DIST_POINTS, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pCRLDistPoint, &ulDataLen))
	{
		CHAR csTemp[8] = {0};
		sprintf_s(csTemp, "[%d]", pCRLDistPoint->cDistPoint);
		strcat_s(csProperty, 512, csTemp);
		for (ULONG ulIndex = 0; ulIndex < pCRLDistPoint->cDistPoint; ulIndex++)
		{
			for (ULONG ulAltEntry = 0; ulAltEntry < pCRLDistPoint->rgDistPoint[ulIndex].DistPointName.FullName.cAltEntry; ulAltEntry++)
			{
				strcat_s(csProperty, 512, W2A(pCRLDistPoint->rgDistPoint[ulIndex].DistPointName.FullName.rgAltEntry[ulAltEntry].pwszURL));
				strcat_s(csProperty, 512, " ");
			}
		}
	}
	else
	{
		return GetLastError();
	}	
	
	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtAuthorityInfoAccess(PCCERT_CONTEXT pCertContext, 
												  LPSTR lpscProperty, 
												  ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	USES_CONVERSION;

	pCertExt = CertFindExtension(szOID_AUTHORITY_INFO_ACCESS, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}

	PCERT_AUTHORITY_INFO_ACCESS pAuthorityInfo = (PCERT_AUTHORITY_INFO_ACCESS)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_AUTHORITY_INFO_ACCESS, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pAuthorityInfo, &ulDataLen))
	{
		CHAR csTemp[256] = {0};
		sprintf_s(csTemp, 256, "[%d]Authority Info Access: \r\n", pAuthorityInfo->cAccDescr);
		strcat_s(csProperty, 512, csTemp);
		for (ULONG ulIndex = 0; ulIndex < pAuthorityInfo->cAccDescr; ulIndex++)
		{
			sprintf_s(csTemp, 256, "Access Method=证书颁发机构颁发者 (%s), \r\n", pAuthorityInfo->rgAccDescr[ulIndex].pszAccessMethod);
			strcat_s(csProperty, 512, csTemp);
			//
			strcat_s(csProperty, 512, W2A(pAuthorityInfo->rgAccDescr[ulIndex].AccessLocation.pwszURL));
		}
	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtNetscapeCertType(PCCERT_CONTEXT pCertContext, 
											   LPSTR lpscProperty, 
											   ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	ULONG ulPropertyLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(szOID_NETSCAPE_CERT_TYPE, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
	
	PCRYPT_BIT_BLOB pBlob = (PCRYPT_BIT_BLOB)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, X509_BITS, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pBlob, &ulDataLen))
	{
		CHAR csTemp[8] = {0};
		sprintf_s(csTemp, 8, "(%x)", pBlob->pbData[0]);
		
		if (pBlob->pbData[0] & NETSCAPE_SSL_CLIENT_AUTH_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "SSL 客户端身份验证; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SSL_SERVER_AUTH_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "SSL 服务器端身份验证; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SMIME_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "SMIME; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SIGN_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "签名; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SSL_CA_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "SSL CA; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SMIME_CA_CERT_TYPE)
		{			
			strcat_s(csProperty, 512, "SMIME CA; ");
		}
		if (pBlob->pbData[0] & NETSCAPE_SIGN_CA_CERT_TYPE)
		{
			strcat_s(csProperty, 512, "Sign CA; ");
		}
			
		strcat_s(csProperty, 512, csTemp);
	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}

ULONG CCSPCertificate::_GetExtDefault(PCCERT_CONTEXT pCertContext, 
									  LPCSTR lpcsOID,
									  LPSTR lpscProperty, 
									  ULONG* pulLen)
{
	ULONG ulRes = 0;
	ULONG ulDataLen = 512;
	BYTE btData[512] = {0};
	CHAR csProperty[512] = {0};
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return CERT_ERR_INVILIDCALL;
	}
	if (!pulLen)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	
	pCertExt = CertFindExtension(lpcsOID, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension); 
	if (!pCertExt)
	{
		return CERT_ERR_ATTR_NOTEXIST;
	}
			
	PCRYPT_DATA_BLOB pDataBlob = (PCRYPT_DATA_BLOB)btData;
	if (CryptDecodeObject(	GLOBAL_ENCODING_TYPE, szOID_SUBJECT_KEY_IDENTIFIER, 
							pCertExt->Value.pbData, pCertExt->Value.cbData, 
							CRYPT_DECODE_NOCOPY_FLAG, pDataBlob, &ulDataLen))
	{
		for (ULONG ulIndex = 0; ulIndex < pDataBlob->cbData; ulIndex++)
		{
			CHAR csKeyID[8] = {0};
			sprintf_s(csKeyID, 8, "%x ", pDataBlob->pbData[ulIndex]);
			strcat_s(csProperty, 512, csKeyID);
		}
	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = strlen(csProperty) + 1;
	}
	if (*pulLen < (strlen(csProperty) + 1))
	{
		return CERT_ERR_BUFFER_TOO_SMALL;
	}
	strcpy_s(lpscProperty, *pulLen, csProperty);

	return CERT_ERR_OK;
}
#pragma once

#include "../Include/ICertificate.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

class COpenSSLCertificate :
	public ICertificate
{
public:
	COpenSSLCertificate(void);
	~COpenSSLCertificate(void);
private:
	ULONG	m_ulCertType;
	ULONG	m_ulCertDataLen;
	LPBYTE	m_pbtCertData;
	X509*	m_pX509;
private:
	ULONG	_GetExtBasicConstraints(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtKeyUsage(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtEnhancedKeyUsage(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtAuthorityIdentifier(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtSubjectIdentifier(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtCRLDistPoints(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtAuthorityInfoAccess(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtNetscapeCertType(X509 *pX509Cert, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtDefault(X509 *pX509Cert, ULONG ulNID, LPSTR lpscProperty, ULONG* pulLen);
public:
	ULONG FromBuffer(LPBYTE lpCertData, ULONG ulDataLen, ULONG ulCertType, LPSTR lpscPassword);
	ULONG ToBuffer(LPBYTE lpCertData, ULONG *pulDataLen);
	ULONG get_Version(ULONG *pulVer);
	ULONG get_SN(LPSTR lptcSN, ULONG *pulLen);
	ULONG get_SignatureAlgOid(LPSTR lpscOid, ULONG *pulLen);
	ULONG get_KeyType(ULONG* pulType);
	ULONG get_KeyUsage(ULONG* lpUsage);
	ULONG get_ValidDate(SYSTEMTIME *ptmStart, SYSTEMTIME *ptmEnd);	
	ULONG get_Issuer(LPSTR lpValue, ULONG *pulLen);
	ULONG get_SubjectName(LPSTR lpValue, ULONG *pulLen);
	ULONG get_PublicKey(LPCERTPUBKEY lpPubKeyBlob);
	ULONG get_HashAlgID(ULONG *pulHashAlg);
	ULONG get_HashValue(LPBYTE lpbtHash, ULONG *pulHashLen);
	ULONG get_ExtensionCnt(ULONG* pulCount);
	ULONG get_ExtensionOid(ULONG ulIndex, LPSTR lpscExtOid, ULONG* pulLen, BOOL *pbIsCrit);
	ULONG get_ExtensionByOid(LPCSTR lpcsExtOid, LPSTR lpscExtension, ULONG* pulLen);
};


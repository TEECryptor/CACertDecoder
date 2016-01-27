/***************************************************
 *	File Name:CSPCertificate.h
 *	Author:yyfzy(QQ:41707352)
 *	Date:2015/04/03
 *	Introduce:This header file is CSP Certificate definition file
 */
#ifndef _CSP_CERTIFICATE_H_
#define	_CSP_CERTIFICATE_H_

#include "../Include/ICertificate.h"
#include <wincrypt.h>

class CCSPCertificate :	public ICertificate
{
public:
	CCSPCertificate(void);
	~CCSPCertificate(void);
private:
	PCCERT_CONTEXT	m_pCertContext;
private:
	ULONG	_DecodeX509Cert(LPBYTE lpCertData, ULONG ulDataLen);
	ULONG	_DecodeP7bCert(LPBYTE lpCertData, ULONG ulDataLen);
	ULONG	_DecodePfxCert(LPBYTE lpCertData, ULONG ulDataLen, LPSTR lpscPassword);
	ULONG	_GetPropertyValue(LPCSTR szOId, DWORD dwSourceId, LPSTR lpValue, DWORD &dwValLen);
	//
	ULONG	_GetExtBasicConstraints(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtKeyUsage(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtEnhancedKeyUsage(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtAuthorityIdentifier(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtSubjectIdentifier(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtCRLDistPoints(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtAuthorityInfoAccess(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtNetscapeCertType(PCCERT_CONTEXT pCertContext, LPSTR lpscProperty, ULONG* pulLen);
	ULONG	_GetExtDefault(PCCERT_CONTEXT pCertContext, LPCSTR lpcsOID, LPSTR lpscProperty, ULONG* pulLen);
public:
	ULONG FromBuffer(LPBYTE lpCertData, ULONG ulDataLen, ULONG ulCertType, LPSTR lpscPassword);
	ULONG ToBuffer(LPBYTE lpCertData, ULONG *pulDataLen);
	ULONG get_Version(ULONG *pulVer);
	ULONG get_SN(LPSTR lpscSN, ULONG *pulLen);
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
#endif	//_CSP_CERTIFICATE_H_


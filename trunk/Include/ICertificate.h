/***************************************************
 *	File Name:ICertificate.h
 *	Author:yyfzy(QQ:41707352)
 *	Date:2015/04/03
 *	Introduce:This header file is Certificate interface definition file
 */

#ifndef _ICERTIFICATE_H_
#define	_ICERTIFICATE_H_

#include <windows.h>

/*	Certificate type	*/
#define	CERT_TYPE_CER			0x01	//X509 certificate, *.cer file format
#define	CERT_TYPE_P7B			0x02	//P7 certificate, *.p7b file format
#define	CERT_TYPE_PFX			0x03	//P12 certificate, *.pfx file format

/*	Certificate decoding type	*/
#define	CERT_USE_CSP_DECODE		0x01	//Use MS CSP API to decode certificate
#define	CERT_USE_OPENSSL_DECODE	0x02	//Use OpenSSL SDK to decode certificate

/*	Certificate public key alg */
#define CERT_KEY_ALG_UNKNOWN	0x00	//Unknown
#define	CERT_KEY_ALG_RSA		0x01	//RSA
#define	CERT_KEY_ALG_ECC		0x02	//SM2(ECC)
#define	CERT_KEY_ALG_DSA		0x03	//DSA
#define	CERT_KEY_ALG_DH			0x04	//DH

/*	Certificate hash alg */
#define	CERT_HASH_ALG_UNKNOWN	0x00	//Unknown
#define	CERT_HASH_ALG_MD5		0x01	//MD5
#define	CERT_HASH_ALG_SHA1		0x02	//SHA1
#define	CERT_HASH_ALG_SHA256	0x03	//SHA256
#define	CERT_HASH_ALG_SHA384	0x04	//SHA384
#define	CERT_HASH_ALG_SHA512	0x05	//SHA512

/*	Certificate usage */
#define	CERT_USAGE_UNKNOWN		0x00	//Unknown
#define	CERT_USAGE_SIGN			0x01	//Sign/Verify certificate
#define	CERT_USAGE_EXCH			0x02	//Encrypt/Decrypt certifcate

/*	RSA public key wrapped type */
#define	RSA_PUBKEY_WRAPPED_CSP	0x01	//Wrapped RSA modulus as CSP format
#define	RSA_PUBKEY_WRAPPED_P11	0x02	//Wrapped RSA modulus as PKCS11 format
#define	RSA_PUBKEY_WRAPPED_GM	0x03	//Wrapped RSA modulus as Guomi SKF format

/*	Certificate siganture alg */
#define CERT_SIGNATURE_ALG_RSA_RSA			"1.2.840.113549.1.1.1"
#define CERT_SIGNATURE_ALG_MD2RSA			"1.2.840.113549.1.1.2"
#define CERT_SIGNATURE_ALG_MD4RSA			"1.2.840.113549.1.1.3"
#define CERT_SIGNATURE_ALG_MD5RSA			"1.2.840.113549.1.1.4"
#define CERT_SIGNATURE_ALG_SHA1RSA			"1.2.840.113549.1.1.5"
#define CERT_SIGNATURE_ALG_SM3SM2			"1.2.156.10197.1.501"

/*	Certificate extension property */
#define	CERT_EXT_AUTHORITY_IDENTIFIER		"2.5.29.1"
#define CERT_EXT_KEY_ATTRIBUTES				"2.5.29.2"
#define CERT_EXT_CERT_POLICIES_95			"2.5.29.3"
#define CERT_EXT_KEY_USAGE_RESTRICTION		"2.5.29.4"
#define CERT_EXT_SUBJECT_ALT_NAME			"2.5.29.7"
#define CERT_EXT_ISSUER_ALT_NAME			"2.5.29.8"
#define CERT_EXT_BASIC_CONSTRAINTS			"2.5.29.10"
#define	CERT_EXT_SUBJECT_DENTIFIER			"2.5.29.14"
#define	CERT_EXT_KEY_USAGE					"2.5.29.15"
#define CERT_EXT_SUBJECT_ALT_NAME2			"2.5.29.17"
#define CERT_EXT_ISSUER_ALT_NAME2			"2.5.29.18"
#define	CERT_EXT_BASIC_CONSTRAINTS2			"2.5.29.19"
#define CERT_EXT_CRL_REASON_CODE			"2.5.29.21"
#define CERT_EXT_REASON_CODE_HOLD			"2.5.29.23"
#define	CERT_EXT_CRL_DIST_POINTS			"2.5.29.31"
#define CERT_EXT_AUTHORITY_KEY_IDENTIFIER2	"2.5.29.35"
#define	CERT_EXT_ENHANCED_KEY_USAGE			"2.5.29.37"
//
#define CERT_EXT_AUTHORITY_INFO_ACCESS		"1.3.6.1.5.5.7.1.1"
#define CERT_EXT_SUBJECT_INFO_ACCESS		"1.3.6.1.5.5.7.1.11"
//
#define CERT_EXT_NETSCAPE_CERT_TYPE			"2.16.840.1.113730.1.1"
#define CERT_EXT_NETSCAPE_BASE_URL			"2.16.840.1.113730.1.2"
#define CERT_EXT_NETSCAPE_REVOCATION_URL	"2.16.840.1.113730.1.3"
#define CERT_EXT_NETSCAPE_CA_REVOCATION_URL "2.16.840.1.113730.1.4"
#define CERT_EXT_NETSCAPE_CERT_RENEWAL_URL	"2.16.840.1.113730.1.7"
#define CERT_EXT_NETSCAPE_CA_POLICY_URL		"2.16.840.1.113730.1.8"
#define CERT_EXT_NETSCAPE_SSL_SERVER_NAME	"2.16.840.1.113730.1.12"
#define CERT_EXT_NETSCAPE_COMMENT			"2.16.840.1.113730.1.13"

/*	Error codes definition	*/
#define	CERT_ERR_OK						0x0
#define	CERT_ERR_FAILED					0x00000001
#define	CERT_ERR_INVILIDCALL			0x00000002
#define	CERT_ERR_INVALIDPARAM			0x00000003
#define	CERT_ERR_NOTSUPPORT				0x00000004
#define	CERT_ERR_OPENFILE_FAILED		0x00000005
#define	CERT_ERR_FILESIZE_ERR			0x00000006
#define	CERT_ERR_BASE64CONVERT_FAILED	0x00000007
#define	CERT_ERR_READFILE_FAILED		0x00000008
#define	CERT_ERR_WRITEFILE_FAILED		0x00000009
#define	CERT_ERR_BUFFER_TOO_SMALL		0x0000000A
#define	CERT_ERR_ALG_UNKNOWN			0x0000000B
#define	CERT_ERR_USAGE_UNKNOWN			0x0000000C
#define	CERT_ERR_CERTDATA_ERR			0x0000000D
#define	CERT_ERR_ATTR_NOTEXIST			0x0000000E

#pragma pack(1)
/*	RSA public key data struct  */
typedef struct tagRSAPubKey
{
	ULONG	ulWrapType;			//RSA_PUBKEY_WRAPPED_CSP,RSA_PUBKEY_WRAPPED_P11 or RSA_PUBKEY_WRAPPED_GM
	ULONG	ulBits;
	BYTE	btExp[4];
	BYTE	btModulus[256];
}RSAPubKey, *LPRSAPUBKEY;

/* ECC public Key data struct  */
typedef struct tagECCPubKey
{
	ULONG	ulBits;
	BYTE	ulX[64];
	BYTE	ulY[64];
}ECCPubKey, *LPECCPUBKEY;

/*	Certificate public key struct */
typedef struct tagCertPubKey
{
	ULONG	ulAlg;				//CERT_KEY_ALG_RSA or CERT_KEY_ALG_ECC
	union
	{
		RSAPubKey	rsa;
		ECCPubKey	ecc;
	};
}CertPubKey, *LPCERTPUBKEY;
#pragma  pack()

/*	Certificate interface */
class ICertificate
{
public:
	ICertificate(){};
	virtual ~ICertificate(){};
public:
	virtual ULONG FromBuffer(LPBYTE lpCertData, ULONG ulDataLen, ULONG ulCertType, LPSTR lpscPassword) = 0;
	virtual ULONG ToBuffer(LPBYTE lpCertData, ULONG *pulDataLen) = 0;
	virtual ULONG get_Version(ULONG *pulVer) = 0;
	virtual ULONG get_SN(LPSTR lpscSN, ULONG *pulLen) = 0;
	virtual ULONG get_SignatureAlgOid(LPSTR lpscOid, ULONG *pulLen) = 0;
	virtual ULONG get_KeyType(ULONG* pulType) = 0;
	virtual ULONG get_KeyUsage(ULONG* lpUsage) = 0;
	virtual ULONG get_ValidDate(SYSTEMTIME *ptmStart, SYSTEMTIME *ptmEnd) = 0;	
	virtual ULONG get_Issuer(LPSTR lpValue, ULONG *pulLen) = 0;
	virtual ULONG get_SubjectName(LPSTR lpValue, ULONG *pulLen) = 0;
	virtual ULONG get_PublicKey(LPCERTPUBKEY lpPubKeyBlob) = 0;
	virtual ULONG get_HashAlgID(ULONG *pulHashAlg) = 0;
	virtual ULONG get_HashValue(LPBYTE lpbtHash, ULONG *pulHashLen) = 0;
	virtual ULONG get_ExtensionCnt(ULONG* pulCount) = 0;
	virtual ULONG get_ExtensionOid(ULONG ulIndex, LPSTR lpscExtOid, ULONG* pulLen, BOOL *pbIsCrit) = 0;
	virtual ULONG get_ExtensionByOid(LPCSTR lpcsExtOid, LPSTR lpscExtension, ULONG* pulLen) = 0;
};

#endif // !_ICERTIFICATE_H_

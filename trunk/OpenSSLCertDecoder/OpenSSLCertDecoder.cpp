// OpenSSLCertDecoder.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "../Include/OpenSSLCertDecoder.h"
#include "../Common/Base64.h"
#include "OpenSSLCertificate.h"


/*
 *	Name:LoadCertFile
 *	Introudce:Load a certificate file (*.cer/*.p7b/*.pfx) and return a ICertificate object
 *	lpscCertFile:[IN]:The file name which will be decoding
 *	lpscPassword:[IN]:The password for pfx file, only used for decoding a pfx file.
 *	pCert:[OUT]:The certificate object returned
 *	Return CERT_ERR_OK if successfully, otherwise return an error code
 */
OPENSSLCERTDECODER_API ULONG LoadCertFile(LPSTR lpscCertFile, LPSTR lpscPassword, ICertificate** pCert)
{	
	ULONG   ulRes = CERT_ERR_OK;
	ULONG	ulCertType = 0;
	ULONG	ulFileSize = 0;
	ULONG	ulReadSize = 0;
	LPBYTE  lpbtCertData = NULL;
	LPSTR  lp = lpscCertFile;
	HANDLE	hCertFile = NULL;

	if (!lpscCertFile || strlen(lpscCertFile) == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	while(*lp != '\0') lp++;
	while(*lp != '.') lp--;
	if (_stricmp(lp, ".cer") == 0)
	{
		ulCertType = CERT_TYPE_CER;
	}
	else if (_stricmp(lp, ".p7b") == 0)
	{
		ulCertType = CERT_TYPE_P7B;
	} 
	else if (_stricmp(lp, ".pfx") == 0)
	{
		ulCertType = CERT_TYPE_PFX;
	}
	else
	{
		return CERT_ERR_NOTSUPPORT;
	}
		
	hCertFile = CreateFileA(lpscCertFile, GENERIC_WRITE|GENERIC_READ, 
		FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hCertFile)
	{
		return CERT_ERR_OPENFILE_FAILED;
	}

	ulFileSize = ::GetFileSize(hCertFile, &ulFileSize);
	if (ulFileSize == 0)
	{
		return CERT_ERR_FILESIZE_ERR;
	}

	lpbtCertData = new BYTE[ulFileSize];
	memset(lpbtCertData, 0, ulFileSize);
	if (!ReadFile(hCertFile, lpbtCertData, ulFileSize, &ulReadSize, NULL))
	{
		ulRes = CERT_ERR_READFILE_FAILED;
		goto FREE_MEMORY;
	}
	
	//	PEM编码(Base64)
	if (lpbtCertData[0] != 0x30 || lpbtCertData[1] != 0x82)
	{
		ULONG ulDataLen = 0;
		LPBYTE lpbtTemp = new BYTE[ulFileSize];

		memcpy_s(lpbtTemp, ulFileSize, lpbtCertData, ulFileSize);
		delete []lpbtCertData;
		lpbtCertData = NULL;

		// 将Base64格式转换为二进制
		ulDataLen = Base64ToBinary((CHAR*)lpbtTemp, ulFileSize, NULL);
		if (ulDataLen == 0)
		{
			ulRes = CERT_ERR_BASE64CONVERT_FAILED;
			delete []lpbtTemp;
			lpbtTemp = NULL;
			goto FREE_MEMORY;
		}
		lpbtCertData = new BYTE[ulDataLen];
		ulDataLen = Base64ToBinary((CHAR*)lpbtTemp, ulFileSize, lpbtCertData);
		if (ulDataLen == 0)
		{
			ulRes = CERT_ERR_BASE64CONVERT_FAILED;
			delete []lpbtTemp;
			lpbtTemp = NULL;
			goto FREE_MEMORY;
		}
	}

	*pCert = new COpenSSLCertificate();
	ulRes = (*pCert)->FromBuffer(lpbtCertData, ulReadSize, ulCertType, lpscPassword);
	if (CERT_ERR_OK != ulRes)
	{
		delete *pCert;
		*pCert = NULL;
		goto FREE_MEMORY;
	}
			
FREE_MEMORY:
	if (lpbtCertData)
	{
		delete []lpbtCertData;
		lpbtCertData = NULL;
	}
	if (hCertFile)
	{
		CloseHandle(hCertFile);
		hCertFile = NULL;
	}

	return ulRes;
}
/*
 *	Name:SaveCertFile
 *	Introudce:Save the certificate object to a *.cer file
 *	lpscCertFile:[IN]:The saving file name which in *.cer format
 *	pCert:[IN]:The certificate object will be saved
 *	Return CERT_ERR_OK if successfully, otherwise return an error code
 */
OPENSSLCERTDECODER_API ULONG SaveCertFile(LPSTR lpscCertFile, ICertificate* pCert)
{
	ULONG   ulRes = CERT_ERR_OK;
	ULONG	ulCertDataLen = 0;
	ULONG	ulWrittenLen = 0;
	LPBYTE	lpbtCertData = NULL;
	HANDLE	hCertFile = NULL;

	if (!pCert)
	{
		return CERT_ERR_INVALIDPARAM;
	}
	if (!lpscCertFile || strlen(lpscCertFile) == 0)
	{
		return CERT_ERR_INVALIDPARAM;
	}

	ulRes = pCert->ToBuffer(NULL, &ulCertDataLen);
	if (CERT_ERR_OK != ulRes || 0 == ulCertDataLen)
	{
		return ulRes;
	}

	lpbtCertData = new BYTE[ulCertDataLen];
	ulRes = pCert->ToBuffer(lpbtCertData, &ulCertDataLen);
	if (CERT_ERR_OK != ulRes)
	{
		goto FREE_MEMORY;
	}

	hCertFile = CreateFileA(lpscCertFile, GENERIC_WRITE|GENERIC_READ, 
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	if (INVALID_HANDLE_VALUE == hCertFile)
	{
		ulRes = CERT_ERR_OPENFILE_FAILED;
		goto FREE_MEMORY;
	}

	if (!WriteFile(hCertFile, lpbtCertData, ulCertDataLen, &ulWrittenLen, NULL) || 0 == ulWrittenLen)
	{
		ulRes = CERT_ERR_WRITEFILE_FAILED;
		goto FREE_MEMORY;
	}

FREE_MEMORY:
	if (hCertFile)
	{
		CloseHandle(hCertFile);
		hCertFile = NULL;
	}
	if (lpbtCertData)
	{
		delete []lpbtCertData;
		lpbtCertData = NULL;
	}

	return ulRes;
}
/*
 *	Name:ReleaseCert
 *	Introudce:Release a certificate object
 *	pCert:[IN]:The certificate object will be released
 */
OPENSSLCERTDECODER_API void ReleaseCert(ICertificate* pCert)
{
	if (pCert)
	{
		delete pCert;
		pCert = NULL;
	}	
}
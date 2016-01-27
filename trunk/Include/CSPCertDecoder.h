/***************************************************
 *	File Name:CSPCertDecoder.h
 *	Author:yyfzy(QQ:41707352)
 *	Date:2015/04/10
 *	Introduce:This header file is export functions for CSPCertDecoder DLL
 */

#ifndef _CSPCERT_DECODER_H_
#define	_CSPCERT_DECODER_H_

// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the CSPCERTDECODER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// CSPCERTDECODER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef CSPCERTDECODER_EXPORTS
#define CSPCERTDECODER_API __declspec(dllexport)
#else
#define CSPCERTDECODER_API __declspec(dllimport)
#endif

#include "ICertificate.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 *	Name:LoadCertFile
 *	Introudce:Load a certificate file (*.cer/*.p7b/*.pfx) and return a ICertificate object
 *	lpscCertFile:[IN]:The file name which will be decoding
 *	lpscPassword:[IN]:The password for pfx file, only used for decoding a pfx file.
 *	pCert:[OUT]:The certificate object returned
 *	Return CERT_ERR_OK if successfully, otherwise return an error code
 */
CSPCERTDECODER_API ULONG LoadCertFile(LPSTR lpscCertFile, LPSTR lpscPassword, ICertificate** pCert);
/*
 *	Name:SaveCertFile
 *	Introudce:Save the certificate object to a *.cer file
 *	lpscCertFile:[IN]:The saving file name which in *.cer format
 *	pCert:[IN]:The certificate object will be saved
 *	Return CERT_ERR_OK if successfully, otherwise return an error code
 */
CSPCERTDECODER_API ULONG SaveCertFile(LPSTR lpscCertFile, ICertificate* pCert);
/*
 *	Name:ReleaseCert
 *	Introudce:Release a certificate object
 *	pCert:[IN]:The certificate object will be released
 */
CSPCERTDECODER_API void ReleaseCert(ICertificate* pCert);

#ifdef __cplusplus
}
#endif


#endif	//_CSPCERT_DECODER_H_
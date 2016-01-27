#include "stdafx.h"
#include "Base64.h"
#include "MemoryBlock.h"

unsigned int BinaryToBase64(const BYTE* pbBinary, DWORD cbBinary, LPTSTR pszOut)
{
	if (pbBinary == NULL || cbBinary == 0)
		return 0;

	if (pszOut == NULL)
	{
		size_t npad = cbBinary % 3;
		size_t size = (npad > 0)? (cbBinary + 3 - npad) : cbBinary; // padded for multiple of 3 bytes
		return (size * 8) / 6 + 1;
	}

	register unsigned int i = 0;
	LPTSTR pszWrite = pszOut;

	const TCHAR base64_map[] = _T("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

	for (i = 0; i < cbBinary - 2; i += 3)
	{
		*pszWrite++ = *(base64_map + ((*(pbBinary+i) >> 2)&0x3f));
		*pszWrite++ = *(base64_map + ((*(pbBinary+i) << 4)&0x30 | (*(pbBinary+i+1)>>4)&0x0f));
		*pszWrite++ = *(base64_map + ((*(pbBinary+i+1)<<2)&0x3C | (*(pbBinary+i+2)>>6)&0x03));
		*pszWrite++ = *(base64_map + (*(pbBinary+i+2)&0x3f));
	}
	pbBinary += i;
	cbBinary -= i;

	if(cbBinary & 0x02 ) /* (i==2) 2 bytes left,pad one byte of '=' */
	{      
		*pszWrite++ = *(base64_map + ((*pbBinary>>2)&0x3f));
		*pszWrite++ = *(base64_map + ((*pbBinary<< 4)&0x30 | (*(pbBinary+1)>>4)&0x0f));
		*pszWrite++ = *(base64_map + ((*(pbBinary+1)<<2)&0x3C) );
		*pszWrite++ = '=';
	}
	else if(cbBinary & 0x01 )  /* (i==1) 1 byte left,pad two bytes of '='  */
	{ 
		*pszWrite++ = *(base64_map + ((*pbBinary >> 2)&0x3f));
		*pszWrite++ = *(base64_map + ((*pbBinary << 4)&0x30));
		*pszWrite++ = '=';
		*pszWrite++ = '=';
	}

	*pszWrite = '\0';

	return pszWrite - pszOut;
}

int FormateB64String(LPCWSTR pwzB64, DWORD dwLen, MemoryBlock<WCHAR>& mbB64Formated)
{
	if (pwzB64 == NULL || dwLen == 0)
		return 0;

	if (_tcschr(pwzB64, '\r') == 0 && _tcschr(pwzB64, '\n') == 0)
		return 0;
	int nB64Index = 0;
	for (UINT i = 0; i < dwLen; i++)
	{
		if ((pwzB64[i] >= 'A' && pwzB64[i] <='Z') 
			|| (pwzB64[i] >='a' && pwzB64[i] <= 'z') 
			|| (pwzB64[i] >= '0' && pwzB64[i] <= '9') 
			|| pwzB64[i] == '+' || pwzB64[i] == '/' || pwzB64[i] == '=')
		{
			*(mbB64Formated.GetPtr() + nB64Index) = pwzB64[i];
			nB64Index++;
		}
		else if (pwzB64[i] == '\r' || pwzB64[i] == '\n')
			continue;
		else
		{
			return 0;
		}
	}
	return nB64Index;
}

unsigned int Base64ToBinary(LPCWSTR pwzB64, DWORD dwLen, BYTE* pbOut)
{
	if (pwzB64 == NULL)
		return 0;
	MemoryBlock<WCHAR> mbB64Formated(dwLen);
	int nLen = FormateB64String(pwzB64, dwLen, mbB64Formated);
	if (nLen != 0)
	{
		dwLen = nLen - nLen % 4;
		pwzB64 = mbB64Formated.GetPtr();
	}
	else
	{
		dwLen = dwLen - dwLen % 4;
	}

	if (pbOut == NULL)
	{
		DWORD cbOut = dwLen * 3 / 4;
		if (*(pwzB64 + dwLen - 2) == '=')
			cbOut -= 2;
		else if (*(pwzB64 + dwLen - 1) == '=')
			cbOut -= 1;
		return cbOut;
	}

	const BYTE B64_offset[256] =
	{
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
		64, 0,   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
		64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
	};

	register unsigned int i = 0;
	BYTE* pbWrite = pbOut;

	dwLen -= 4;
	while(i < dwLen)
	{
		*pbWrite++ = (B64_offset[*(pwzB64+i)] << 2 | B64_offset[*(pwzB64+i+1)] >>4);
		*pbWrite++ = (B64_offset[*(pwzB64+i+1)]<<4 | B64_offset[*(pwzB64+i+2)] >>2);
		*pbWrite++ = (B64_offset[*(pwzB64+i+2)]<<6 | B64_offset[*(pwzB64+i+3)] );
		i += 4;
	}
	pwzB64 += i;

	if (*(pwzB64 + 2) == '=')
	{
		*pbWrite = (B64_offset[*pwzB64] << 2 | B64_offset[*(pwzB64 + 1)] >> 4);
	}
	else if (*(pwzB64 + 3) == '=')
	{
		*pbWrite++ = (B64_offset[*pwzB64] << 2 | B64_offset[*(pwzB64 + 1)] >> 4);
		*pbWrite = (B64_offset[*(pwzB64+1)]<<4 | B64_offset[*(pwzB64 + 2)] >> 2);
	}
	else
	{
		*pbWrite++ = (B64_offset[*(pwzB64)] << 2 | B64_offset[*(pwzB64+1)] >>4);
		*pbWrite++ = (B64_offset[*(pwzB64+1)]<<4 | B64_offset[*(pwzB64+2)]>>2);
		*pbWrite = (B64_offset[*(pwzB64+2)]<<6 | B64_offset[*(pwzB64+3)] );
	}

	return pbWrite - pbOut + 1;
}

unsigned int _internalBase64ToBinary(LPCSTR pszB64, DWORD dwLen, BYTE* pbOut)
{
	dwLen = dwLen - dwLen % 4;

	if (pbOut == NULL)
	{
		DWORD cbOut = dwLen * 3 / 4;
		if (*(pszB64 + dwLen - 2) == '=')
			cbOut -= 2;
		else if (*(pszB64 + dwLen - 1) == '=')
			cbOut -= 1;
		return cbOut;
	}

	const BYTE B64_offset[256] =
	{
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
		52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
		64, 0,   1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
		15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
		64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
		64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
	};

	register unsigned int i = 0;
	BYTE* pbWrite = pbOut;

	dwLen -= 4;
	while(i < dwLen)
	{
		*pbWrite++ = (B64_offset[*(pszB64+i)] << 2 | B64_offset[*(pszB64+i+1)] >>4);
		*pbWrite++ = (B64_offset[*(pszB64+i+1)]<<4 | B64_offset[*(pszB64+i+2)] >>2);
		*pbWrite++ = (B64_offset[*(pszB64+i+2)]<<6 | B64_offset[*(pszB64+i+3)] );
		i += 4;
	}
	pszB64 += i;

	if (*(pszB64 + 2) == '=')
	{
		*pbWrite = (B64_offset[*pszB64] << 2 | B64_offset[*(pszB64 + 1)] >> 4);
	}
	else if (*(pszB64 + 3) == '=')
	{
		*pbWrite++ = (B64_offset[*pszB64] << 2 | B64_offset[*(pszB64 + 1)] >> 4);
		*pbWrite = (B64_offset[*(pszB64+1)]<<4 | B64_offset[*(pszB64 + 2)] >> 2);
	}
	else
	{
		*pbWrite++ = (B64_offset[*(pszB64)] << 2 | B64_offset[*(pszB64+1)] >>4);
		*pbWrite++ = (B64_offset[*(pszB64+1)]<<4 | B64_offset[*(pszB64+2)]>>2);
		*pbWrite = (B64_offset[*(pszB64+2)]<<6 | B64_offset[*(pszB64+3)] );
	}

	return pbWrite - pbOut + 1;
}


int FormateB64String(LPCSTR pszB64, DWORD dwLen, MemoryBlock<CHAR>& mbB64Formated)
{
	if (pszB64 == NULL || dwLen == 0)
		return 0;

	if (strchr(pszB64, '\r') == 0 && strchr(pszB64, '\n') == 0)
		return 0;
	int nB64Index = 0;
	for (UINT i = 0; i < dwLen; i++)
	{
		if ((pszB64[i] >= 'A' && pszB64[i] <='Z') 
			|| (pszB64[i] >='a' && pszB64[i] <= 'z') 
			|| (pszB64[i] >= '0' && pszB64[i] <= '9') 
			|| pszB64[i] == '+' || pszB64[i] == '/' || pszB64[i] == '=')
		{
			*(mbB64Formated.GetPtr() + nB64Index) = pszB64[i];
			nB64Index++;
		}
		else if (pszB64[i] == '\r' || pszB64[i] == '\n')
			continue;
		else
		{
			return 0;
		}
	}
	return nB64Index;
}

unsigned int Base64ToBinary(LPCSTR pszB64, DWORD dwLen, BYTE* pbOut)
{
	if (pszB64 == NULL)
		return 0;
	MemoryBlock<CHAR> mbB64Formated(dwLen);
	int nLen = FormateB64String(pszB64, dwLen, mbB64Formated);
	if (nLen != 0)
	{
		dwLen = nLen;
		pszB64 = mbB64Formated.GetPtr();
	}

	return _internalBase64ToBinary(pszB64, dwLen, pbOut);
}

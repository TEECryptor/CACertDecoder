#pragma once

#include <windows.h>
#include <TCHAR.h>

unsigned int BinaryToBase64(const BYTE* pbBinary, DWORD cbBinary, LPTSTR pszOut);
unsigned int Base64ToBinary(LPCWSTR pszB64, DWORD dwLen, BYTE* pbOut);
unsigned int Base64ToBinary(LPCSTR pszB64, DWORD dwLen, BYTE* pbOut);
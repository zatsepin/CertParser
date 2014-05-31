#include <Windows.h>

#ifndef __UTIL_H
#define __UTIL_H

#include <Windows.h>
#include <Wincrypt.h>

DWORD load_file(LPCTSTR file, BYTE *pbBuffer);

DWORD get_name_field(LPCSTR szName, LPCSTR szField, char *szOut);

LPSTR cert_name_to_str(PCERT_NAME_BLOB pName, DWORD *pdwOutSize);

LPSTR file_time_to_str(FILETIME ftTime);

LPSTR decode_utf8_string(BYTE *pbData, DWORD cbData);

void *decode_object(BYTE *pbData, DWORD cbData, LPCSTR szType, DWORD *dwOutSize);

LPSTR binary2hex(BYTE *pbData, DWORD cbData);

#endif // __UTIL_H
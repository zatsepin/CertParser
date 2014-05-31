#include <stdio.h>
#include "util.h"

DWORD get_name_field(LPCSTR szName, LPCSTR szField, char *szOut)
{
     char *szNameDup = NULL;
     char *context1 = NULL;
     char *context2 = NULL;
     char *szToken = NULL;
     char *szTokenValue = NULL;
     DWORD dwOutSize = 0;

     if(!szName || !szField)
          goto end;

     szNameDup = _strdup(szName);
     if(!szNameDup)
          goto end;

     szToken = strtok_s(
                    szNameDup,
                    ";",
                    &context1);
     while(szToken)
     {
          szTokenValue = strtok_s(
                         szToken,
                         "=",
                         &context2);
          if(!szTokenValue)
               goto end;
          while(*szTokenValue == ' ')
               ++szTokenValue;

          if(!strcmp(szTokenValue, szField))
          {
               szTokenValue = strtok_s(
                              NULL,
                              "=",
                              &context2);
               if(!szTokenValue)
                    goto end;

               dwOutSize = strlen(szTokenValue);
               if(szOut)
                    memcpy(szOut, szTokenValue, dwOutSize);

               goto end;
          }

          szToken = strtok_s(
                         NULL,
                         ";",
                         &context1);
     }
end:
     if(szNameDup)
          free(szNameDup);

     return dwOutSize;

}

DWORD load_file(LPCTSTR file, BYTE *pbBuffer)
{
     HANDLE hFile = 0;
     DWORD dwSize = 0;

     if(!file)
          goto end;

     hFile = CreateFile(
                    file,
                    GENERIC_READ,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
     if(!hFile)
          goto end;

     dwSize = GetFileSize(
                    hFile,
                    NULL);

     if(INVALID_FILE_SIZE == dwSize) {
          dwSize = 0;
          goto end;
     }

     if(!pbBuffer)
          goto end;

     {
          DWORD dwRead = 0;
          if(!ReadFile(
                    hFile,
                    pbBuffer,
                    dwSize,
                    &dwRead,
                    NULL)) 
          {
               dwSize = 0;     
               goto end;
          }

          if(dwRead != dwSize) {
               dwSize = 0;
               goto end;
          }
     }

end:
     if(hFile)
          CloseHandle(hFile);

     return dwSize;
}

LPSTR cert_name_to_str(PCERT_NAME_BLOB pName, DWORD *pdwOutSize)
{
     LPSTR szOut = NULL;
     
     if(!pName)
          return NULL;

     *pdwOutSize = CertNameToStr(
                         X509_ASN_ENCODING,
                         pName,
                         CERT_OID_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG,
                         NULL,
                         0);
     if(!*pdwOutSize)
          return NULL;

     szOut = (LPSTR) calloc(*pdwOutSize, 1);
     if(!szOut)
          return NULL;

     *pdwOutSize = CertNameToStr(
                         X509_ASN_ENCODING,
                         pName,
                         CERT_OID_NAME_STR | CERT_NAME_STR_SEMICOLON_FLAG,
                         szOut,
                         *pdwOutSize);
     if(!*pdwOutSize) {
          free(szOut);
          return NULL;
     }

     return szOut;
}

LPSTR file_time_to_str(FILETIME ftTime)
{
     CHAR tmp[1024] = {'\0'};
     LPSTR szOut = NULL;
     SYSTEMTIME stUTC, stLocal;
     DWORD dwRet;

     FileTimeToSystemTime(&ftTime, &stUTC);
     SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

     dwRet = sprintf_s(tmp, sizeof(tmp), "%02d.%02d.%d  %02d:%02d:%02d",
                         stLocal.wDay, stLocal.wMonth, stLocal.wYear,
                         stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

     if(dwRet <= 0)
          return NULL;

     szOut = (LPSTR)calloc(strlen(tmp) + 1, 1);
     if(!szOut)
          return NULL;

     memcpy(szOut, tmp, strlen(tmp));

     return szOut;
}

void *decode_object(BYTE *pbData, DWORD cbData, LPCSTR szType, DWORD *dwOutSize)
{
     void *pOut = NULL;
     *dwOutSize = 0;
     
     if(!pbData || !cbData)
          return 0;

     if(!CryptDecodeObject(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    szType,
                    pbData,
                    cbData,
                    0,
                    NULL,
                    dwOutSize))
     {
          *dwOutSize = 0;
          return NULL;
     }

     pOut = malloc(*dwOutSize);
     if(!pOut)
     {
          *dwOutSize = 0;
          return NULL;     
     }

     if(!CryptDecodeObject(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    szType,
                    pbData,
                    cbData,
                    0,
                    pOut,
                    dwOutSize))
     {
          *dwOutSize = 0;
          free(pOut);
          return NULL;
     }

     return pOut;
}

LPSTR binary2hex(BYTE *pbData, DWORD cbData)
{
     LPSTR szOut = NULL;
     DWORD dwOutSize = 0;

     if(!pbData || !cbData)
          return NULL;

     if(!CryptBinaryToString(
                    pbData,
                    cbData,
                    CRYPT_STRING_HEX,
                    NULL,
                    &dwOutSize))
          return NULL;

     szOut = (LPSTR) calloc(dwOutSize + 1, 1);
     if(!szOut)
          return NULL;

     if(!CryptBinaryToString(
                    pbData,
                    cbData,
                    CRYPT_STRING_HEX,
                    szOut,
                    &dwOutSize))
     {
          free(szOut);
          return NULL;
     }

     return szOut;
}


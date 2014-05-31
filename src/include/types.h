#ifndef __TYPES_H
#define __TYPES_H

#include <Windows.h>
#include "defs.h"

typedef enum __QUALIFY_CERT_TYPE
{
     Undef = 0,
     Private,
     Legal
} QUALIFY_CERT_TYPE;

typedef struct __QUALIFY_CERT_NAME_ATTR
{
     LPSTR szOID;
     LPSTR szDescription;
     BOOL bCritical;
     LPSTR szValue;
     DWORD dwValue;
} QUALIFY_CERT_NAME_ATTR, *PQUALIFY_CERT_NAME_ATTR;

typedef struct __QUALIFY_CERT_NAME
{
     PQUALIFY_CERT_NAME_ATTR  pAttrs;
     DWORD                    dwAttrsCount;
} QUALIFY_CERT_NAME, *PQUALIFY_CERT_NAME;

typedef struct __QUALIFY_CERT_ISSUER_SIGN_TOOL
{
     LPSTR               szSignTool;
     LPSTR               szSignToolCert;
     LPSTR               szCATool;
     LPSTR               szCAToolCert;
} QUALIFY_CERT_ISSUER_SIGN_TOOL, *PQUALIFY_CERT_ISSUER_SIGN_TOOL;

typedef struct __QUALIFY_CERT_AUTHORITY
{
     PQUALIFY_CERT_NAME                 pIssuerName;
     LPSTR                              szAuthorityCertSerialNumber;
     PQUALIFY_CERT_ISSUER_SIGN_TOOL     pSignTool;
} QUALIFY_CERT_AUTHORITY, *PQUALIFY_CERT_AUTHORITY;

typedef struct __QUALIFY_CERT_INFO
{
     QUALIFY_CERT_TYPE        type;
     PQUALIFY_CERT_NAME       pSubjectName;
     QUALIFY_CERT_AUTHORITY   pAuthority;
     LPSTR                    szNotBefore;
     LPSTR                    szNotAfter;
     LPSTR                    szSubjectSignTool;
     LPSTR                    szKeyUsage;
     LPSTR                    szPublicKeyAlgorithm;
     LPSTR                    szPublicKey;
     LPSTR                    szCertPolicies;
     LPSTR                    szSignatureAlgorithm;
     LPSTR                    szSignature;
} QUALIFY_CERT_INFO, *PQUALIFY_CERT_INFO;


typedef struct __KEY_USAGE
{
     BYTE                     usage;
     LPCSTR                   szDescription;
} KEY_USAGE;
#endif // __TYPES_H
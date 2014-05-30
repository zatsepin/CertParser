#ifndef __TYPES_H
#define __TYPES_H

#include <Windows.h>

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

typedef struct __QUALIFY_CERT_INFO
{
     QUALIFY_CERT_TYPE   type;
     PQUALIFY_CERT_NAME  pSubjectName;
     PQUALIFY_CERT_NAME  pIssuerName;
} QUALIFY_CERT_INFO, *PQUALIFY_CERT_INFO;

#endif // __TYPES_H
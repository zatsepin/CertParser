#ifndef __QUALIFY_CERT_H
#define __QUALIFY_CERT_H

#include "types.h"

// QUALIFY_CERT_INFO 
PQUALIFY_CERT_INFO QUALIFY_CERT_INFO_new(PCCERT_CONTEXT pCertificate);
int QUALIFY_CERT_INFO_print(PQUALIFY_CERT_INFO pCertInfo);
void QUALIFY_CERT_INFO_free(PQUALIFY_CERT_INFO pCertInfo);

// QUALIFY_CERT_NAME
PQUALIFY_CERT_NAME QUALIFY_CERT_NAME_new();
int QUALIFY_CERT_NAME_load(PQUALIFY_CERT_NAME pCertName, PCCERT_CONTEXT pCertificate);
void QUALIFY_CERT_NAME_free(PQUALIFY_CERT_NAME pCertName);
int QUALIFY_CERT_NAME_add_attr(PQUALIFY_CERT_NAME pCertName, PQUALIFY_CERT_NAME_ATTR pCertNameAttr);
PQUALIFY_CERT_NAME_ATTR QUALIFY_CERT_NAME_get_attr(PQUALIFY_CERT_NAME pCertName, DWORD dwIndex);

// QUALIFY_CERT_NAME_ATTR
PQUALIFY_CERT_NAME_ATTR QUALIFY_CERT_NAME_ATTR_new(LPCSTR szOid, LPCSTR szDecription, BOOL isCritical);
int QUALIFY_CERT_NAME_ATTR_set_value(PQUALIFY_CERT_NAME_ATTR pCertNameAttr, LPCSTR szValue, DWORD dwValue);
void QUALIFY_CERT_NAME_ATTR_free(PQUALIFY_CERT_NAME_ATTR pCertNameAttr);

// QUALIFY_CERT_ISSUER_SIGN_TOOL
PQUALIFY_CERT_ISSUER_SIGN_TOOL QUALIFY_CERT_ISSUER_SIGN_TOOL_new(PCERT_EXTENSION pExt);
void QUALIFY_CERT_ISSUER_SIGN_TOOL_free(PQUALIFY_CERT_ISSUER_SIGN_TOOL pSignTool);

#endif // __QUALIFY_CERT_H
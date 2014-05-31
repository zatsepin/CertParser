#include <stdio.h>

#include "qualify_cert.h"
#include "defs.h"
#include "util.h"

const QUALIFY_CERT_NAME_ATTR name_attrs[NAME_ID_NUMS] = 
     {
          { COMMON_NAME_OID,                 "commonName",                 0 },
          { SURNAME_OID,                     "surname",                    1 },
          { GIVEN_NAME_OID,                  "givenName",                  0 },
          { COUNTRY_NAME_OID,                "countryName",                0 },
          { STATE_OF_PROVINCE_NAME_OID,      "stateOfProvinceName",        0 },
          { LOCALITY_NAME_OID,               "localityname",               0 },
          { STREET_ADDRESS_OID,              "streetAddress",              0 },
          { ORGANIZATION_NAME_OID,           "organizationName",           0 },
          { ORGANIZATION_UNIT_NAME_OID,      "organizationUnitName",       0 },
          { TITLE_OID,                       "title",                      1 },
          { OGRN_OID,                        "ORGN",                       0 },
          { SNILS_OID,                       "SNILS",                      1 },
          { INN_OID,                         "INN",                        0 },
          { EMAIL_OID,                       "emailAddress",               0 },
     };

const KEY_USAGE key_usages[] = 
     {
          // byte 0
          { CERT_DIGITAL_SIGNATURE_KEY_USAGE,     "Цифровая подпись" },
          { CERT_NON_REPUDIATION_KEY_USAGE,       "Неотрекаемость" },
          { CERT_KEY_ENCIPHERMENT_KEY_USAGE,      "Шифрование ключей" },
          { CERT_DATA_ENCIPHERMENT_KEY_USAGE,     "Шифрование данных" },
          { CERT_KEY_AGREEMENT_KEY_USAGE,         "Согласование ключей" },
          { CERT_KEY_CERT_SIGN_KEY_USAGE,         "Проверка подписи" },
          { CERT_CRL_SIGN_KEY_USAGE,              "Подписание списка отзыва" },
          { CERT_OFFLINE_CRL_SIGN_KEY_USAGE,      "Автономное подписание списка отзыва" },
          { CERT_ENCIPHER_ONLY_KEY_USAGE,         "Только шифрование" },
          // byte 1
          { CERT_DECIPHER_ONLY_KEY_USAGE,         "Только расшифрование" },
     };

static LPSTR get_authority_serial_number(BYTE *pbData, DWORD cbData)
{
     PCERT_AUTHORITY_KEY_ID_INFO pCertAuthKeyId;
     DWORD dwSize = 0;
     LPSTR szOut = NULL;
     if(!pbData || !cbData)
          return NULL;

     pCertAuthKeyId = (PCERT_AUTHORITY_KEY_ID_INFO)decode_object(
                                                       pbData,
                                                       cbData,
                                                       X509_AUTHORITY_KEY_ID,
                                                       &dwSize);
     if(!pCertAuthKeyId || !dwSize)
          return NULL;

     szOut = binary2hex(pCertAuthKeyId->CertSerialNumber.pbData, pCertAuthKeyId->CertSerialNumber.cbData);

     return szOut;
}

static LPSTR get_key_usage(BYTE *pbData, DWORD cbData)
{
     LPSTR szOut = NULL;
     CHAR buf[4096] = {'\0'};
     DWORD dwOutSize = 0;
     PCRYPT_BIT_BLOB pBits = NULL;
     DWORD idx = 0;

     if(!pbData || !cbData)
          return NULL;

     pBits = (PCRYPT_BIT_BLOB)decode_object(pbData, cbData, X509_KEY_USAGE, &dwOutSize);
     if(!pBits)
          goto end;

     if(!pBits->pbData || !pBits->cbData)
          goto end;

     // byte 1
     for(; idx < sizeof(key_usages)/sizeof(key_usages[0]) - 1; ++idx)
     {
          if(*pBits->pbData & key_usages[idx].usage)
          {
               if(strlen(buf))
                    strcat_s(buf, sizeof(buf), ", ");
               strcat_s(buf, sizeof(buf), key_usages[idx].szDescription);
          }
     }

     if(pBits->cbData > 1)
     {
          // byte 2
          idx = sizeof(key_usages)/sizeof(key_usages[0]) - 1;
          if(*++pBits->pbData & key_usages[idx].usage)
          {
               if(strlen(buf))
                    strcat_s(buf, sizeof(buf), ", ");
               strcat_s(buf, sizeof(buf), key_usages[idx].szDescription);     
          }
     }

     szOut = _strdup(buf);
end:
     if(pBits)
          free(pBits);

     return szOut;
}

static LPSTR get_cert_policies(BYTE *pbData, DWORD cbData)
{
     LPSTR szOut = NULL;
     DWORD dwSize = 0;
     PCERT_POLICIES_INFO pCertPolicies = NULL;
     CHAR buf[8192] = {'\0'};
     DWORD idx = 0;

     if(!pbData || !cbData)
          return NULL;

     pCertPolicies = (PCERT_POLICIES_INFO)decode_object(
                                                       pbData,
                                                       cbData,
                                                       X509_CERT_POLICIES,
                                                       &dwSize);
     if(!pCertPolicies)
          return NULL;

     for(; idx < pCertPolicies->cPolicyInfo; ++idx)
     {
          if(strlen(buf))
               strcat_s(buf, sizeof(buf), ", ");
          strcat_s(buf, sizeof(buf), pCertPolicies->rgPolicyInfo[idx].pszPolicyIdentifier);
     }

     if(strlen(buf) < 0)
          goto end;

     szOut = _strdup(buf);

end:
     if(pCertPolicies)
          free(pCertPolicies);
     return szOut;
}

/////////////////////////////////////////////////////////////////////////
// QUALIFY_CERT_INFO
/////////////////////////////////////////////////////////////////////////
PQUALIFY_CERT_INFO QUALIFY_CERT_INFO_new(PCCERT_CONTEXT pCertificate)
{
     PQUALIFY_CERT_INFO pCertInfo = NULL;
     unsigned int idx = 0, rv = 0;

     if(!pCertificate || !pCertificate->pCertInfo)
          goto end;

     pCertInfo = (PQUALIFY_CERT_INFO)calloc(sizeof(QUALIFY_CERT_INFO), 1);
     if(!pCertInfo)
          goto end;

     pCertInfo->pAuthority.pIssuerName = QUALIFY_CERT_NAME_new(&pCertificate->pCertInfo->Issuer);
     pCertInfo->pSubjectName = QUALIFY_CERT_NAME_new(&pCertificate->pCertInfo->Subject);

     pCertInfo->szNotBefore = file_time_to_str(pCertificate->pCertInfo->NotBefore);
     pCertInfo->szNotAfter = file_time_to_str(pCertificate->pCertInfo->NotAfter);

     pCertInfo->szPublicKey = binary2hex(
                                   pCertificate->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
                                   pCertificate->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData);

     pCertInfo->szPublicKeyAlgorithm = _strdup(pCertificate->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);

     pCertInfo->szSignature = binary2hex(
                                   (pCertificate->pbCertEncoded + pCertificate->cbCertEncoded - GOST3410_SIGNATURE_SIZE),
                                   GOST3410_SIGNATURE_SIZE);
     pCertInfo->szSignatureAlgorithm = _strdup(pCertificate->pCertInfo->SignatureAlgorithm.pszObjId);

     for(; idx < pCertificate->pCertInfo->cExtension; ++idx)
     {
          PCERT_EXTENSION pExt = &pCertificate->pCertInfo->rgExtension[idx];
          if(!pExt)
               break;
          if(!strcmp(pExt->pszObjId, AUTHORITY_KEY_ID_OID))
          {
               pCertInfo->pAuthority.szAuthorityCertSerialNumber = get_authority_serial_number(pExt->Value.pbData, pExt->Value.cbData);
               continue;
          }
          else if(!strcmp(pExt->pszObjId, AUTHORITY_SIGN_TOOL_OID))
          {
               pCertInfo->pAuthority.pSignTool = QUALIFY_CERT_ISSUER_SIGN_TOOL_new(pExt);
               continue;
          }
          else if(!strcmp(pExt->pszObjId, SUBJECT_SIGN_TOOL_OID))
          {
               pCertInfo->szSubjectSignTool = (LPSTR)decode_object(pExt->Value.pbData, pExt->Value.cbData, ASN_1_UTF8_STRING, NULL);
               continue;
          }
          if(!strcmp(pExt->pszObjId, KEY_USAGE_OID))
          {
               pCertInfo->szKeyUsage = get_key_usage(pExt->Value.pbData, pExt->Value.cbData);
               continue;
          }
          if(!strcmp(pExt->pszObjId, CERT_POLICIES_OID))
          {
               pCertInfo->szCertPolicies = get_cert_policies(pExt->Value.pbData, pExt->Value.cbData);
          }
     }

     rv = 1;
end:
     if(!rv)
     {
          QUALIFY_CERT_INFO_free(pCertInfo);
          pCertInfo = NULL;
     }

     return pCertInfo;
}

void QUALIFY_CERT_INFO_free(PQUALIFY_CERT_INFO pCertInfo)
{
     if(pCertInfo)
     {
          QUALIFY_CERT_NAME_free(pCertInfo->pSubjectName); pCertInfo->pSubjectName = NULL;
          QUALIFY_CERT_NAME_free(pCertInfo->pAuthority.pIssuerName); pCertInfo->pAuthority.pIssuerName = NULL;
          if(pCertInfo->pAuthority.szAuthorityCertSerialNumber) 
          {
               free(pCertInfo->pAuthority.szAuthorityCertSerialNumber);
               pCertInfo->pAuthority.szAuthorityCertSerialNumber = NULL;
          }
          if(pCertInfo->pAuthority.pSignTool)
          {
               QUALIFY_CERT_ISSUER_SIGN_TOOL_free(pCertInfo->pAuthority.pSignTool);
               pCertInfo->pAuthority.pSignTool = NULL;
          }
          if(pCertInfo->szKeyUsage)
          {
               free(pCertInfo->szKeyUsage);
               pCertInfo->szKeyUsage = NULL;
          }
          if(pCertInfo->szPublicKey)
          {
               free(pCertInfo->szPublicKey);
               pCertInfo->szPublicKey = NULL;
          }
          if(pCertInfo->szPublicKeyAlgorithm)
          {
               free(pCertInfo->szPublicKeyAlgorithm);
               pCertInfo->szPublicKeyAlgorithm = NULL;
          }
          if(pCertInfo->szCertPolicies)
          {
               free(pCertInfo->szCertPolicies);
               pCertInfo->szCertPolicies = NULL;
          }
          if(pCertInfo->szSignatureAlgorithm)
          {
               free(pCertInfo->szSignatureAlgorithm);
               pCertInfo->szSignatureAlgorithm = NULL;
          }
          if(pCertInfo->szSignature)
          {
               free(pCertInfo->szSignature);
               pCertInfo->szSignature = NULL;
          }
          pCertInfo->type = Undef;          
     }
}

int QUALIFY_CERT_INFO_print(PQUALIFY_CERT_INFO pCertInfo)
{
     DWORD idx = 0;
     if(!pCertInfo)
          return 0;

     printf("Subject:\n");
     for(; idx < pCertInfo->pSubjectName->dwAttrsCount; ++idx)
     {
          printf("\t%s [%s] == %s\n", 
                    pCertInfo->pSubjectName->pAttrs[idx].szDescription,
                    pCertInfo->pSubjectName->pAttrs[idx].szOID,
                    pCertInfo->pSubjectName->pAttrs[idx].szValue);
     }

     printf("Authority:\n");
     for(idx = 0; idx < pCertInfo->pAuthority.pIssuerName->dwAttrsCount; ++idx)
     {
          printf("\t%s [%s] == %s\n", 
                    pCertInfo->pAuthority.pIssuerName->pAttrs[idx].szDescription,
                    pCertInfo->pAuthority.pIssuerName->pAttrs[idx].szOID,
                    pCertInfo->pAuthority.pIssuerName->pAttrs[idx].szValue);
     }
     printf("\n");
     printf("\tCertificate serial number: %s\n", pCertInfo->pAuthority.szAuthorityCertSerialNumber);
     if(pCertInfo->pAuthority.pSignTool)
     {
          printf("\tIssuer sign tool:\n");
          printf("\t\tSign tool: %s\n", pCertInfo->pAuthority.pSignTool->szSignTool);
          printf("\t\tSign tool cert: %s\n", pCertInfo->pAuthority.pSignTool->szSignToolCert);
          printf("\t\tCA tool: %s\n", pCertInfo->pAuthority.pSignTool->szCATool);
          printf("\t\tCA tool cert: %s\n", pCertInfo->pAuthority.pSignTool->szCAToolCert);
     }
     printf("Time validity:\n");
     printf("\tNot before: %s\n", pCertInfo->szNotBefore);
     printf("\tNot after: %s\n", pCertInfo->szNotAfter);

     printf("Subject sign tool: %s\n", pCertInfo->szSubjectSignTool);
     printf("Subject public key algorithm: %s\n", pCertInfo->szPublicKeyAlgorithm);
     printf("Subject public key:\n%s\n", pCertInfo->szPublicKey);
     printf("Key usage: %s\n", pCertInfo->szKeyUsage);

     printf("Cert policies: %s\n", pCertInfo->szCertPolicies);

     printf("Signature algorithm: %s\n", pCertInfo->szSignatureAlgorithm);
     printf("Signature:\n%s\n", pCertInfo->szSignature);

     return 1;
}

/////////////////////////////////////////////////////////////////////////
// QUALIFY_CERT_NAME
/////////////////////////////////////////////////////////////////////////
PQUALIFY_CERT_NAME QUALIFY_CERT_NAME_new(PCERT_NAME_BLOB pName)
{
     PQUALIFY_CERT_NAME pCertName = NULL;
     PQUALIFY_CERT_NAME_ATTR pAttr = NULL;
     LPSTR szName = NULL;
     DWORD dwName = 0;
     CHAR szNameField[256] = {'\0'};
     DWORD dwNameFieldSize = 0;
     int idx = 0, rv = 0;
      
     pCertName = (PQUALIFY_CERT_NAME)calloc(sizeof(QUALIFY_CERT_NAME), 1);
     if(!pCertName)
          goto end;

     if(!pName) {
          rv = 1;
          goto end;
     }
     
     szName = cert_name_to_str(pName, &dwName);
     if(!szName || !dwName)
          goto end;

     for(; idx < NAME_ID_NUMS; ++idx)
     {
          memset(szNameField, 0, sizeof(szNameField));               
          dwNameFieldSize = get_name_field(
                                   szName,
                                   name_attrs[idx].szOID,
                                   szNameField);
          if(!dwNameFieldSize)
               continue;

          pAttr = QUALIFY_CERT_NAME_ATTR_new(
                                   name_attrs[idx].szOID,
                                   name_attrs[idx].szDescription,
                                   name_attrs[idx].bCritical);

          if(!pAttr)
               goto end;

          if(!QUALIFY_CERT_NAME_ATTR_set_value(
                                   pAttr,
                                   szNameField,
                                   dwNameFieldSize))
               goto end;

          if(!QUALIFY_CERT_NAME_add_attr(
                              pCertName,
                              pAttr)) 
          {
               QUALIFY_CERT_NAME_ATTR_free(pAttr);
               goto end;
          }          
     }

     rv = 1;

end: 
     if(!rv)
     {
          QUALIFY_CERT_NAME_free(pCertName);
          pCertName = NULL;
     }
     return pCertName;
}

int QUALIFY_CERT_NAME_load(PQUALIFY_CERT_NAME pCertName, PCCERT_CONTEXT pCertificate)
{
     return 0;
}

void QUALIFY_CERT_NAME_free(PQUALIFY_CERT_NAME pCertName)
{

}

int QUALIFY_CERT_NAME_add_attr(PQUALIFY_CERT_NAME pCertName, PQUALIFY_CERT_NAME_ATTR pCertNameAttr)
{
     PQUALIFY_CERT_NAME_ATTR tmp = NULL;

     if(!pCertName || !pCertNameAttr)
          return 0;

     tmp = (PQUALIFY_CERT_NAME_ATTR)realloc(pCertName->pAttrs, (pCertName->dwAttrsCount + 1) * sizeof(QUALIFY_CERT_NAME_ATTR));
     if(!tmp)
          return 0;

     pCertName->pAttrs = tmp;
     pCertName->pAttrs[pCertName->dwAttrsCount] = *pCertNameAttr;
     return ++pCertName->dwAttrsCount;
}

PQUALIFY_CERT_NAME_ATTR QUALIFY_CERT_NAME_get_attr(PQUALIFY_CERT_NAME pCertName, DWORD dwIndex)
{
     return NULL;
}

/////////////////////////////////////////////////////////////////////////
// QUALIFY_CERT_NAME_ATTR
/////////////////////////////////////////////////////////////////////////
PQUALIFY_CERT_NAME_ATTR QUALIFY_CERT_NAME_ATTR_new(LPCSTR szOid, LPCSTR szDecription, BOOL isCritical)
{
     PQUALIFY_CERT_NAME_ATTR pAttr = NULL;

     if(!szOid || !szDecription)
          return NULL;

     pAttr = (PQUALIFY_CERT_NAME_ATTR)calloc(sizeof(QUALIFY_CERT_NAME_ATTR), 1);
     if(!pAttr)
          return NULL;

     if((NULL == (pAttr->szOID = _strdup(szOid)))
     || (NULL == (pAttr->szDescription = _strdup(szDecription))))
     {
          QUALIFY_CERT_NAME_ATTR_free(pAttr);
          return NULL;
     }

     pAttr->bCritical = isCritical;

     return pAttr;

}

int QUALIFY_CERT_NAME_ATTR_set_value(PQUALIFY_CERT_NAME_ATTR pCertNameAttr, LPCSTR szValue, DWORD dwValue)
{
     if(!pCertNameAttr)
          return 0;

     if(pCertNameAttr->szValue == szValue)
          return 1;

     if(pCertNameAttr->szValue) {
          free(pCertNameAttr->szValue);
          pCertNameAttr->szValue = NULL;
     }
     pCertNameAttr->dwValue = 0;

     if(!szValue || !dwValue)
          return 1;

     pCertNameAttr->szValue = _strdup(szValue);
     if(!pCertNameAttr->szValue)
          return 0;

     pCertNameAttr->dwValue = dwValue;

     return 1;
}

void QUALIFY_CERT_NAME_ATTR_free(PQUALIFY_CERT_NAME_ATTR pCertNameAttr)
{
	if(pCertNameAttr)
	{
		if(pCertNameAttr->szValue) {
			free(pCertNameAttr->szValue); pCertNameAttr->szValue = NULL;
		}
		if(pCertNameAttr->szOID) {
			free(pCertNameAttr->szOID); pCertNameAttr->szOID = NULL;
		}
		if(pCertNameAttr->szDescription) {
			free(pCertNameAttr->szDescription); pCertNameAttr->szDescription = NULL;
		}

		free(pCertNameAttr);
	}
}

/////////////////////////////////////////////////////////////////////////
// QUALIFY_CERT_ISSUER_SIGN_TOOL
/////////////////////////////////////////////////////////////////////////
PQUALIFY_CERT_ISSUER_SIGN_TOOL QUALIFY_CERT_ISSUER_SIGN_TOOL_new(PCERT_EXTENSION pExt)
{
     PQUALIFY_CERT_ISSUER_SIGN_TOOL pSignTool = NULL;
     BYTE *pbTmp = NULL;
     DWORD dwLeftSize = 0;
     DWORD dwChunkSize = 0;

     if(!pExt || strcmp(pExt->pszObjId, AUTHORITY_SIGN_TOOL_OID))
          return NULL;

     pSignTool = (PQUALIFY_CERT_ISSUER_SIGN_TOOL) calloc(sizeof(QUALIFY_CERT_ISSUER_SIGN_TOOL), 1);
     if(!pSignTool)
          return NULL;

     pbTmp = pExt->Value.pbData;
     dwLeftSize = pExt->Value.cbData;
     while((*pbTmp != 0x0c) && dwLeftSize)
     {
          ++pbTmp;
          --dwLeftSize;
     }
     dwChunkSize = *(pbTmp + 1);
     if(dwChunkSize >= dwLeftSize)
     {
          QUALIFY_CERT_ISSUER_SIGN_TOOL_free(pSignTool);
          return NULL;
     }     
     pSignTool->szSignTool = decode_utf8_string(pbTmp, 0);
     pbTmp += dwChunkSize + 1;
     dwLeftSize -= dwChunkSize;

     while((*pbTmp != 0x0c) && dwLeftSize)
     {
          ++pbTmp;
          --dwLeftSize;
     }
     dwChunkSize = *(pbTmp + 1);
     if(dwChunkSize >= dwLeftSize)
     {
          QUALIFY_CERT_ISSUER_SIGN_TOOL_free(pSignTool);
          return NULL;
     }
     pSignTool->szCATool = decode_utf8_string(pbTmp, 0);
     pbTmp += dwChunkSize + 1;
     dwLeftSize -= dwChunkSize;

     while((*pbTmp != 0x0c) && dwLeftSize)
     {
          ++pbTmp;
          --dwLeftSize;
     }
     dwChunkSize = *(pbTmp + 1);
     if(dwChunkSize >= dwLeftSize)
     {
          QUALIFY_CERT_ISSUER_SIGN_TOOL_free(pSignTool);
          return NULL;
     }
     pSignTool->szSignToolCert = decode_utf8_string(pbTmp, 0);
     pbTmp += dwChunkSize + 1;
     dwLeftSize -= dwChunkSize;

     while((*pbTmp != 0x0c) && dwLeftSize)
     {
          ++pbTmp;
          --dwLeftSize;
     }
     dwChunkSize = *(pbTmp + 1);
     if(dwChunkSize >= dwLeftSize)
     {
          QUALIFY_CERT_ISSUER_SIGN_TOOL_free(pSignTool);
          return NULL;
     }
     pSignTool->szCAToolCert = decode_utf8_string(pbTmp, 0);
     pbTmp += dwChunkSize + 1;
     dwLeftSize -= dwChunkSize;

     return pSignTool;
}
void QUALIFY_CERT_ISSUER_SIGN_TOOL_free(PQUALIFY_CERT_ISSUER_SIGN_TOOL pSignTool)
{
     if(pSignTool)
     {
          if(pSignTool->szSignTool) {
               free(pSignTool->szSignTool);
               pSignTool->szSignTool = NULL;
          }
          if(pSignTool->szSignToolCert) {
               free(pSignTool->szSignToolCert);
               pSignTool->szSignToolCert = NULL;
          }
          if(pSignTool->szCATool) {
               free(pSignTool->szCATool);
               pSignTool->szCATool = NULL;
          }
          if(pSignTool->szCAToolCert) {
               free(pSignTool->szCAToolCert);
               pSignTool->szCAToolCert = NULL;
          }
          free(pSignTool);
     }
}

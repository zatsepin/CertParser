#include <stdio.h>

#include "qualify_cert.h"
#include "defs.h"
#include "util.h"

/////////////////////////////////////////////////////////////////////////
// QUALIFY_CERT_INFO
/////////////////////////////////////////////////////////////////////////
PQUALIFY_CERT_INFO QUALIFY_CERT_INFO_new(PCCERT_CONTEXT pCertificate)
{
     PQUALIFY_CERT_INFO pCertInfo = NULL;
     int rv = 0;

     if(!pCertificate || !pCertificate->pCertInfo)
          goto end;

     pCertInfo = (PQUALIFY_CERT_INFO)calloc(sizeof(QUALIFY_CERT_INFO), 1);
     if(!pCertInfo)
          goto end;

     if(NULL == (pCertInfo->pIssuerName = QUALIFY_CERT_NAME_new(&pCertificate->pCertInfo->Issuer)))
          goto end;
     
     if(NULL == (pCertInfo->pSubjectName = QUALIFY_CERT_NAME_new(&pCertificate->pCertInfo->Subject)))
          goto end;

     if(NULL == (pCertInfo->szNotBefore = file_time_to_str(pCertificate->pCertInfo->NotBefore)))
          goto end;
     if(NULL == (pCertInfo->szNotAfter = file_time_to_str(pCertificate->pCertInfo->NotAfter)))
          goto end;

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
          QUALIFY_CERT_NAME_free(pCertInfo->pIssuerName); pCertInfo->pIssuerName = NULL;
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

     printf("Issuer:\n");
     for(idx = 0; idx < pCertInfo->pIssuerName->dwAttrsCount; ++idx)
     {
          printf("\t%s [%s] == %s\n", 
                    pCertInfo->pIssuerName->pAttrs[idx].szDescription,
                    pCertInfo->pIssuerName->pAttrs[idx].szOID,
                    pCertInfo->pIssuerName->pAttrs[idx].szValue);
     }

     printf("Time validity:\n");
     printf("\tNot before: %s\n", pCertInfo->szNotBefore);
     printf("\tNot after: %s\n", pCertInfo->szNotAfter);

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

     for(; idx < ID_NUMS; ++idx)
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

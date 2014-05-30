#include <stdio.h>
#include "qualify_cert.h"
#include "util.h"

int main()
{
#if 0     
     BYTE *pbSigned = NULL;
     DWORD cbSigned = 0;
#endif
     PQUALIFY_CERT_INFO pCertInfo = NULL;
     BYTE *pbCert = NULL;
     DWORD cbCert = 0;
     HCERTSTORE hStore = 0;
     PCERT_CONTEXT pSigner = NULL;
     LPSTR szName = NULL;
     DWORD dwNameSize = 0;

     int result = -1;
#if 0
     // Load PKCS#7 from file
     cbSigned = load_file(
                    TEXT("p7sign.exe.p7b"),
                    NULL);
     if(!cbSigned)
          goto end;

     pbSigned = (BYTE *) malloc(cbSigned * sizeof(BYTE));
     if(!pbSigned)
          goto end;
     
     cbSigned = load_file(
                    TEXT("p7sign.exe.p7b"),
                    pbSigned);
     if(!cbSigned)
          goto end; 

     // Check if a there is a one signer only
     {
          LONG lNumberOfCerts = CryptGetMessageSignerCount(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        pbSigned,
                                        cbSigned);
          if(1 != lNumberOfCerts)
               goto end;
     }

     // Get a signer certificate
     {
          hStore = CryptGetMessageCertificates(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        0,
                                        CERT_SYSTEM_STORE_CURRENT_USER,
                                        pbSigned,
                                        cbSigned);
          if(!hStore)
               goto end;

          pSigner = (PCERT_CONTEXT)CertEnumCertificatesInStore(
                                        hStore,
                                        NULL);
          if(!pSigner)
               goto end;
     }
#endif
#if 1
     cbCert = load_file(
                    TEXT("testoff.cer"),
                    NULL);

     pbCert = (BYTE *) malloc(cbCert * sizeof(BYTE));
     if(!pbCert)
          goto end;
     
     cbCert = load_file(
                    TEXT("testoff.cer"),
                    pbCert);
     if(!cbCert)
          goto end;


     pSigner = (PCERT_CONTEXT)CertCreateCertificateContext(
                              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              pbCert,
                              cbCert);
     if(!pSigner)
          goto end;
#endif

     pCertInfo = QUALIFY_CERT_INFO_new(pSigner);
     if(!pCertInfo)
          goto end;

     if(!QUALIFY_CERT_INFO_print(pCertInfo))
          goto end;

     result = 0;

end:     
#if 0
     if(pbSigned)
          free(pbSigned);
#endif
     if(pbCert)
          free(pbCert);
     if(hStore)
          CertCloseStore(hStore, 0);
     if(pSigner)
          CertFreeCertificateContext(pSigner);
     if(pCertInfo)
          QUALIFY_CERT_INFO_free(pCertInfo);
     return result;
}
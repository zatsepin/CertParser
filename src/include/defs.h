#ifndef __DEFS_H
#define __DEFS_H

// OIDs
#define COMMON_NAME_OID                 "2.5.4.3"                // 1
#define SURNAME_OID                     "2.5.4.4"                // 2
#define GIVEN_NAME_OID                  "2.5.4.42"               // 3
#define COUNTRY_NAME_OID                "2.5.4.6"                // 4
#define STATE_OF_PROVINCE_NAME_OID      "2.5.4.8"                // 5
#define LOCALITY_NAME_OID               "2.5.4.7"                // 6
#define STREET_ADDRESS_OID              "2.5.4.9"                // 7
#define ORGANIZATION_NAME_OID           "2.5.4.10"               // 8
#define ORGANIZATION_UNIT_NAME_OID      "2.5.4.11"               // 9
#define TITLE_OID                       "2.5.4.12"               // 10
#define OGRN_OID                        "1.2.643.100.1"          // 11
#define SNILS_OID                       "1.2.643.100.3"          // 12
#define INN_OID                         "1.2.643.3.131.1.1"      // 13
#define EMAIL_OID                       "1.2.840.113549.1.9.1"   // 14

#define NAME_ID_NUMS                    14

#define AUTHORITY_KEY_ID_OID            "2.5.29.35"
#define SUBJECT_SIGN_TOOL_OID           "1.2.643.100.111"
#define AUTHORITY_SIGN_TOOL_OID         "1.2.643.100.112"
#define KEY_USAGE_OID                   "2.5.29.15"
#define CERT_POLICIES_OID               "2.5.29.32"

#define ASN_1_UTF8_STRING               ((LPCSTR) 101)

#define GOST3410_SIGNATURE_SIZE         64

#endif // __DEFS_H
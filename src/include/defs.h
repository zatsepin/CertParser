#ifndef __DEFS_H
#define __DEFS_H

#include "types.h"

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

#define ID_NUMS                         14

const QUALIFY_CERT_NAME_ATTR name_attrs[ID_NUMS] = 
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

#endif // __DEFS_H
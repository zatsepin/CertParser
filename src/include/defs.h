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

#define ID_NUMS                         13

const QUALIFY_CERT_NAME_ATTR name_attrs[] = 
     {
          { "2.5.4.3",             "commonName",                 0 },
          { "2.5.4.4",             "surname",                    1 },
          { "2.5.4.42",            "givenName",                  0 },
          { "2.5.4.6",             "countryName",                0 },
          { "2.5.4.8",             "stateOfProvinceName",        0 },
          { "2.5.4.7",             "localityname",               0 },
          { "2.5.4.9",             "streetAddress",              0 },
          { "2.5.4.10",            "organizationName",           0 },
          { "2.5.4.11",            "organizationUnitName",       0 },
          { "2.5.4.12",            "title",                      1 },
          { "1.2.643.100.1",       "ORGN",                       0 },
          { "1.2.643.100.3",       "SNILS",                      1 },
          { "1.2.643.3.131.1.1",   "INN",                        0 },
     };

/*
const LPCSTR oids[ID_NUMS] = 
     {
          "2.5.4.3",
          "2.5.4.4",
          "2.5.4.42",
          "2.5.4.6",
          "2.5.4.8",
          "2.5.4.7",
          "2.5.4.9",
          "2.5.4.10",
          "2.5.4.11",
          "2.5.4.12",
          "1.2.643.100.1",
          "1.2.643.100.3",
          "1.2.643.3.131.1.1",
     };

const LPCSTR descriptions[ID_NUMS] = 
     {
          "commonName",
          "surname",
          "givenName",
          "countryName",
          "stateOfProvinceName",
          "localityname",
          "streetAddress",
          "organizationName",
          "organizationUnitName",
          "title",
          "ORGN",
          "SNILS",
          "INN",
     };
*/
#endif // __DEFS_H
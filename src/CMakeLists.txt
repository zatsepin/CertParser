SET(CERT_PARSER_SOURCE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
SET(CERT_PARSER_INCLUDE_DIRECTORIES ${CERT_PARSER_SOURCE_DIRECTORY}/include)

SET(CERT_PARSER_SOURCES ${CERT_PARSER_SOURCE_DIRECTORY}/main.c
			${CERT_PARSER_SOURCE_DIRECTORY}/qualify_cert.c
			${CERT_PARSER_INCLUDE_DIRECTORIES}/qualify_cert.h
			${CERT_PARSER_SOURCE_DIRECTORY}/util.c
			${CERT_PARSER_INCLUDE_DIRECTORIES}/util.h
			${CERT_PARSER_INCLUDE_DIRECTORIES}/defs.h
			${CERT_PARSER_INCLUDE_DIRECTORIES}/types.h)

INCLUDE_DIRECTORIES(${CERT_PARSER_INCLUDE_DIRECTORIES})

ADD_EXECUTABLE(cert_parser ${CERT_PARSER_SOURCES})

TARGET_LINK_LIBRARIES(cert_parser crypt32.lib)
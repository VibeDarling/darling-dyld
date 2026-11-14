// The expat interface the PAC-leaf test uses, declared locally so the test does not need a host expat.h.
#ifndef H0_EXPAT_DECL_H
#define H0_EXPAT_DECL_H

typedef struct XML_ParserStruct *XML_Parser;
typedef char XML_Char;

enum XML_Status { XML_STATUS_ERROR = 0, XML_STATUS_OK = 1 };
enum XML_Error { XML_ERROR_NONE = 0, XML_ERROR_TAG_MISMATCH = 7 };

typedef void (*XML_StartElementHandler)(void *userData, const XML_Char *name, const XML_Char **atts);
typedef void (*XML_EndElementHandler)(void *userData, const XML_Char *name);
typedef void (*XML_CharacterDataHandler)(void *userData, const XML_Char *s, int len);

const XML_Char *XML_ExpatVersion(void);
XML_Parser XML_ParserCreate(const XML_Char *encoding);
void XML_SetUserData(XML_Parser parser, void *userData);
void XML_SetElementHandler(XML_Parser parser, XML_StartElementHandler start, XML_EndElementHandler end);
void XML_SetCharacterDataHandler(XML_Parser parser, XML_CharacterDataHandler handler);
enum XML_Status XML_Parse(XML_Parser parser, const char *s, int len, int isFinal);
enum XML_Error XML_GetErrorCode(XML_Parser parser);
void XML_ParserFree(XML_Parser parser);

#endif

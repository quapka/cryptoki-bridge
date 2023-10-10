#define CK_PTR *

#ifdef _WIN32
#define STDCALL __stdcall
#else
#define STDCALL
#endif

#define CK_DECLARE_FUNCTION(returnType, name) \
    returnType STDCALL name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
    returnType(*STDCALL name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
    returnType(*STDCALL name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

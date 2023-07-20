# Generated from httpserver.pro.

#####################################################################
## Nostr Module:
#####################################################################

include_directories(../thirdparty/secp256k1/include/)

add_compile_definitions(ENABLE_MODULE_ECDH)
add_compile_definitions(ENABLE_MODULE_RECOVERY)
add_compile_definitions(ENABLE_MODULE_EXTRAKEYS)
add_compile_definitions(ENABLE_MODULE_SCHNORRSIG)
add_compile_definitions(ENABLE_MODULE_ELLSWIFT)

include_directories(${OPENSSL_INCLUDE_DIRS})

qt_internal_add_module(Nostr
    SOURCES
        qnostr.h
        qnostrrelay.h
        qtnostr_global.h
        
        qnostr.cpp
        qnostrrelay.cpp
        
        ../thirdparty/secp256k1/src/secp256k1.c 
        ../thirdparty/secp256k1/src/precomputed_ecmult_gen.c 
        ../thirdparty/secp256k1/src/precomputed_ecmult.c

    LIBRARIES
        Qt::Core
        Qt::Network
        Qt::WebSockets
        ${OPENSSL_LIBRARIES}
)

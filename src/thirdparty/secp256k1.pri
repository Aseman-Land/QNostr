INCLUDEPATH += \
    $$PWD/secp256k1/include/

DEFINES += \
    ENABLE_MODULE_ECDH \
    ENABLE_MODULE_RECOVERY \
    ENABLE_MODULE_EXTRAKEYS \
    ENABLE_MODULE_SCHNORRSIG \
    ENABLE_MODULE_ELLSWIFT

SOURCES += \
    $$PWD/secp256k1/src/secp256k1.c \
    $$PWD/secp256k1/src/precomputed_ecmult_gen.c \
    $$PWD/secp256k1/src/precomputed_ecmult.c

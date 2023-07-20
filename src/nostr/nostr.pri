INCLUDEPATH += .
QT = network core websockets

CONFIG += c++17

linux: !android {
    isEmpty(OPENSSL_LIB_PATH): OPENSSL_LIB_PATH = /usr
} else {
    isEmpty(OPENSSL_LIB_PATH): OPENSSL_LIB_PATH = $$[QT_INSTALL_DATA]
}
isEmpty(OPENSSL_LIB_PATH): OPENSSL_LIB_PATH = $$OPENSS_LIB_PATH
exists($$OPENSSL_LIB_PATH/include/openssl/conf.h) {
    message(OpenSSL libs found on $$OPENSSL_LIB_PATH)
} else {
    OPENSSL_LIB_PATH = $$getenv(OPENSSL_LIB_PATH)
    exists($$OPENSSL_LIB_PATH/include/openssl/conf.h) {
        message(OpenSSL libs found on $$OPENSSL_LIB_PATH)
    } else {
        error(Could not find OpenSSL lib directory. Please set it using OPENSSL_LIB_PATH argument)
    }
}

INCLUDEPATH += \
    $$OPENSSL_LIB_PATH/include

win32-msvc* {
    LIBS += -L$$[QT_INSTALL_LIBS] -L$$OPENSSL_LIB_PATH/lib -llibssl -llibcrypto
} else {
    LIBS += -L$$[QT_INSTALL_LIBS] -L$$OPENSSL_LIB_PATH/lib -lssl -lcrypto
}

include(../thirdparty/thirdparty.pri)

SOURCES += \
    $$PWD/qnostr.cpp \
    $$PWD/qnostrrelay.cpp

HEADERS += \
    $$PWD/qnostr.h \
    $$PWD/qnostrrelay.h \
    $$PWD/qtnostr_global.h

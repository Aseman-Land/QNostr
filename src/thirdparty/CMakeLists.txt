# Generated from httpserver.pro.

#####################################################################
## Nostr Module:
#####################################################################

qt_internal_add_module(Nostr
    SOURCES
        qnostr.h
        qnostrrelay.h
        qtnostr_global.h
        qnostr.cpp
        qnostrrelay.cpp

    LIBRARIES
        Qt::Core
        Qt::Network
        Qt::WebSockets
)

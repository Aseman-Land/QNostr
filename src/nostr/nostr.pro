load(qt_build_config)

TARGET = QNostr

MODULE = nostr


load(qt_module)

DEFINES += LIBQTNOSTR_CORE_LIBRARY

include(nostr.pri)

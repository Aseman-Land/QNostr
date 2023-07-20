#ifndef NOSTR_CORE_GLOBAL_H
#define NOSTR_CORE_GLOBAL_H

#include <QtCore/qglobal.h>

#ifndef QT_STATIC
#if defined(LIBQTNOSTR_CORE_LIBRARY)
#  define LIBQTNOSTR_CORE_EXPORT Q_DECL_EXPORT
#else
#  define LIBQTNOSTR_CORE_EXPORT Q_DECL_IMPORT
#endif
#else
#define LIBQTNOSTR_CORE_EXPORT
#endif

#endif // NOSTR_CORE_GLOBAL_H

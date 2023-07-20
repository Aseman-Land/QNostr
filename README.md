# QNostr-Module
Standard Nostr module for Qt written using C++ and QtWebSockets.

## How to Build

To build it for Qt5 run below commands:

```bash
git clone "https://github.com/Aseman-Land/qnostr.git"
cd qnostr
mkdir build && cd build
qmake -r ..
make -j4
sudo make install
```

And for Qt6:

```bash
git clone "https://github.com/Aseman-Land/qnostr.git"
cd qnostr
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=release -DCMAKE_INSTALL_PREFIX=/usr ..
make -j4
sudo make install
```

## How to add it to Projects

It's easy. Just add below line to your qmake's `.pro` file:

```qmake
QT += nostr
```

Or for cmake

```cmake
find_package(Qt6 6.0.0 CONFIG REQUIRED COMPONENTS Nostr)
```

## How to use it

```C++
#include <QCoreApplication>

#include <QNostr>

const auto secret = QNostr::generateNewSecret();

QNostr relay(secret);
relay.addRelay(QUrl("wss://RELAY_ADDRESS"));

connect(&relay, &QNostr::connected, [](const QUrl &relay){
    qDebug() << relay << "Connected";
});
connect(&relay, &QNostr::newEvent, [](const QString &subscribeId, const QNostrRelay::Event &event, bool storedEvent, const QUrl &relay){
    qDebug() << relay << subscribeId << event.content << storedEvent;
});
connect(&relay, &QNostr::disconnected, [](const QUrl &relay){
    qDebug() << relay << "Disconnected";
});

QNostrRelay::Request req;
req.authors << "AUTHOR_PKEY";
req.kinds << 1;
req.limit = 10;

qDebug() << relay.sendRequest(req);
```


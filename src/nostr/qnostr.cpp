#include "qnostr.h"

#include <QWebSocket>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

class QNostr::Private
{
public:
    QList<QUrl> relaysOrder;
    QHash<QUrl, QNostrRelay*> relaysHash;

    QByteArray publicKey;
    QByteArray privateKey;
};

QNostr::QNostr(const QString &secretKey, QObject *parent)
    : QObject(parent)
{
    p = new Private;
    p->privateKey = QNostrRelay::extractPrivateKey(secretKey.toLatin1());
    p->publicKey = QNostrRelay::compressedPublicKey(secretKey);
}

QNostr::QNostr(const QString &publicKey, const QString &privateKey, QObject *parent)
    : QObject(parent)
{
    p = new Private;
    p->publicKey = publicKey.toLatin1();
    p->privateKey = privateKey.toLatin1();
}

QNostr::~QNostr()
{
    delete p;
}

QString QNostr::publicKey() const
{
    return QString::fromLatin1(p->publicKey);
}

QString QNostr::privateKey() const
{
    return QString::fromLatin1(p->privateKey);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

QString QNostr::generateNewSecret()
{
    auto keyPair = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!keyPair)
    {
        qDebug() << "Failed to generate SECP key pair.";
        return QString();
    }

    if (EC_KEY_generate_key(keyPair) != 1)
    {
        qDebug() << "Failed to generate SECP key pair.";
        EC_KEY_free(keyPair);
        return QString();
    }

    BIO* privateKeyBio = BIO_new(BIO_s_mem());
    if (!privateKeyBio)
    {
        qDebug() << "Failed to create BIO for private key.";
        return QString();
    }

    if (!PEM_write_bio_ECPrivateKey(privateKeyBio, keyPair, nullptr, nullptr, 0, nullptr, nullptr))
    {
        qDebug() << "Failed to write private key to BIO.";
        BIO_free(privateKeyBio);
        return QString();
    }

    BUF_MEM* privateKeyMem;
    BIO_get_mem_ptr(privateKeyBio, &privateKeyMem);
    std::string privateKeyStr(privateKeyMem->data, privateKeyMem->length);

    // Clean up
    BIO_free_all(privateKeyBio);
    EC_KEY_free(keyPair);

    auto list = QString::fromStdString(privateKeyStr).split('\n', Qt::SkipEmptyParts);

    return list.mid(1, list.size()-2).join(QString());
}

#pragma GCC diagnostic pop

QList<QUrl> QNostr::relays() const
{
    return p->relaysOrder;
}

void QNostr::setRelays(const QList<QUrl> &relays)
{
    if (p->relaysOrder == relays)
        return;

    QSet<QUrl> set;
    for (const auto &url: relays)
    {
        set.insert(url);
        addRelay(url);
    }
    for (const auto &url: p->relaysOrder)
        if (!set.contains(url))
            removeRelay(url);

    p->relaysOrder = relays;
    Q_EMIT relaysChanged();
}

void QNostr::addRelay(const QUrl &url)
{
    if (p->relaysHash.contains(url))
        return;

    auto r = new QNostrRelay(url, QString::fromLatin1(p->publicKey), QString::fromLatin1(p->privateKey), this);

    connect(r, &QNostrRelay::failed, this, [this, url](const QString &id, const QString &reason){ Q_EMIT failed(id, reason, url); });
    connect(r, &QNostrRelay::successfully, this, [this, url](const QString &id){ Q_EMIT successfully(id, url); });
    connect(r, &QNostrRelay::error, this, [this, url](QAbstractSocket::SocketError err){ Q_EMIT error(err, url); });
    connect(r, &QNostrRelay::sslErrors, this, [this, url](const QList<QSslError> &errors){ Q_EMIT sslErrors(errors, url); });
    connect(r, &QNostrRelay::newEvent, this, [this, url](const QString &subscribeId, const QNostrRelay::Event &event, bool storedEvent){ Q_EMIT newEvent(subscribeId, event, storedEvent, url); });
    connect(r, &QNostrRelay::notice, this, [this, url](const QString &msg){ Q_EMIT notice(msg, url); });
    connect(r, &QNostrRelay::syncEventsFinished, this, [this, url](const QString &subscribeId){ Q_EMIT syncEventsFinished(subscribeId, url); });
    connect(r, &QNostrRelay::disconnected, this, [this, url](){ Q_EMIT QNostr::disconnected(url); });
    connect(r, &QNostrRelay::connected, this, [this, url](){ Q_EMIT QNostr::connected(url); });

    r->start();

    p->relaysHash[url] = r;
    p->relaysOrder << url;
}

void QNostr::removeRelay(const QUrl &url)
{
    if (!p->relaysHash.contains(url))
        return;

    auto r = p->relaysHash.take(url);
    delete r;
    p->relaysOrder.removeAll(url);
}

QString QNostr::sendEvent(const QString &content)
{
    QNostrRelay::Event e;
    e.content = content;
    e.kind = 1;

    return sendEvent(e);
}

QString QNostr::sendEvent(QNostrRelay::Event event)
{
    QNostrRelay::prepareEvent(event, p->publicKey, p->privateKey);
    for (const auto &r: p->relaysHash)
        r->sendEvent(event, true);
    return event.id.value();

}

QString QNostr::sendRequest(QNostrRelay::Request request)
{
    request.subscriptionId = QUuid::createUuid().toString(QUuid::WithoutBraces).toUpper();
    for (const auto &r: p->relaysHash)
        r->sendRequest(request);
    return request.subscriptionId.value();
}

void QNostr::sendClose(const QNostrRelay::Close &request)
{
    for (const auto &r: p->relaysHash)
        r->sendClose(request);
}

void QNostr::sendClose(const QString &subscriptionId)
{
    for (const auto &r: p->relaysHash)
        r->sendClose(subscriptionId);
}

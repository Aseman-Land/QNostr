#include "qnostrrelay.h"
#include "secp256k1_schnorrsig.h"

#include <QUuid>
#include <QWebSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQueue>
#include <QTimer>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

using namespace std::string_literals;

const std::string qnostr_privateKeyHeader = "-----BEGIN EC PRIVATE KEY-----\n"s;
const std::string qnostr_privateKeyFooter = "\n-----END EC PRIVATE KEY-----\n"s;

class QNostrRelay::Private
{
public:
    QWebSocket *ws;
    bool started = false;
    QTimer *reconnectTimer;

    QUrl relay;
    QByteArray privateKey;
    QByteArray publicKey;

    QQueue<QString> queue;
    QSet<QString> activeRequests;

    struct RequestState {
        bool eose = false;
    };

    QHash<QString, RequestState> requests;
};

QNostrRelay::QNostrRelay(const QUrl &relay, const QString &secretKey, QObject *parent)
    : QObject(parent)
{
    p = new Private;
    p->relay = relay;
    p->privateKey = extractPrivateKey(secretKey.toLatin1());
    p->publicKey = compressedPublicKey(secretKey);

    init();
}

QNostrRelay::QNostrRelay(const QUrl &relay, const QString &publicKey, const QString &privateKey, QObject *parent)
    : QObject(parent)
{
    p = new Private;
    p->relay = relay;
    p->privateKey = privateKey.toLatin1();
    p->publicKey = publicKey.toLatin1();

    init();
}

QNostrRelay::~QNostrRelay()
{
    delete p;
}

void QNostrRelay::start()
{
    p->started = true;
    p->ws->open(p->relay);
    p->reconnectTimer->stop();
}

void QNostrRelay::stop()
{
    p->started = false;
    p->ws->close();
    p->reconnectTimer->stop();
}

QString QNostrRelay::sendEvent(const QString &content)
{
    Event e;
    e.content = content;
    e.kind = 1;

    return sendEvent(e);
}

QString QNostrRelay::sendEvent(Event e, bool prepared)
{
    if (!prepared)
        prepareEvent(e, p->publicKey, p->privateKey);

    const auto command = e.serialize();
    if (p->ws->state() == QAbstractSocket::ConnectedState)
        p->ws->sendTextMessage(command);
    else
        p->queue << command;

    return e.id.value();
}


void QNostrRelay::prepareEvent(Event &e, const QByteArray &publicKey, const QByteArray &privateKey)
{
    if (!e.pubkey)
        e.pubkey = QByteArray::fromBase64(publicKey).mid(1).toHex().toLower();

    if (!e.created_at) e.created_at = QDateTime::currentDateTime();
    if (!e.id) e.id = calculateId(e);
    if (!e.sig) e.sig = sign(QByteArray::fromHex(e.id.value().toLatin1()), privateKey).toHex().toLower();
}

QString QNostrRelay::sendRequest(Request r)
{
    if (!r.subscriptionId)
        r.subscriptionId = QUuid::createUuid().toString(QUuid::WithoutBraces).toUpper();

    const auto command = r.serialize();
    if (p->ws->state() == QAbstractSocket::ConnectedState)
        p->ws->sendTextMessage(command);

    p->activeRequests.insert(command);
    return r.subscriptionId.value();
}

void QNostrRelay::sendClose(const Close &r)
{
    const auto command = r.serialize();
    if (p->ws->state() == QAbstractSocket::ConnectedState)
        p->ws->sendTextMessage(command);
    else
        p->queue << command;

    p->activeRequests.remove(command);
}

void QNostrRelay::sendClose(const QString &subscriptionId)
{
    Close c;
    c.subscriptionId = subscriptionId;
    sendClose(c);
}

void QNostrRelay::serverConnected()
{
    // Take a breath
    if (p->ws->state() != QAbstractSocket::ConnectedState)
        return;

    // Re/Active all requests
    for (const auto &r: p->activeRequests)
        p->ws->sendTextMessage(r);

    // Send queued commands
    while (p->queue.size())
        p->ws->sendTextMessage( p->queue.takeFirst() );
}

void QNostrRelay::serverDisonnected()
{
    if (!p->started)
    {
        Q_EMIT disconnected();
        return;
    }

    qDebug() << p->relay.toString() << " disconnected. Reconnect in 5 seconds...";

    p->reconnectTimer->stop();
    p->reconnectTimer->start(5000);
}

void QNostrRelay::analizeData(const QString &data)
{
    auto doc = QJsonDocument::fromJson(data.toUtf8());

    if (!doc.isArray())
    {
        qDebug() << "Bad command received!";
        return;
    }

    const auto arr = doc.array();
    const auto cmd = arr.at(0).toString();
    if (cmd == QStringLiteral("EVENT"))
    {
        const auto subId = arr.at(1).toString();
        const auto state = p->requests[subId];
        auto event = Event::deserialize(arr.at(2).toObject());
        Q_EMIT newEvent(subId, event, !state.eose);
    }
    else if (cmd == QStringLiteral("OK"))
    {
        const auto id = arr.at(1).toString();
        const auto state = arr.at(2).toBool();
        if (state)
            Q_EMIT successfully(id);
        else
            Q_EMIT failed(id, arr.at(3).toString());
    }
    else if (cmd == QStringLiteral("EOSE"))
    {
        const auto subId = arr.at(1).toString();
        auto &state = p->requests[subId];
        state.eose = true;
        Q_EMIT syncEventsFinished(subId);
    }
    else if (cmd == QStringLiteral("EVENT"))
    {
        Q_EMIT notice( arr.at(1).toString() );
    }
}

void QNostrRelay::init()
{
    p->reconnectTimer = new QTimer(this);
    p->reconnectTimer->setSingleShot(true);

    connect(p->reconnectTimer, &QTimer::timeout, this, &QNostrRelay::start);

    p->ws = new QWebSocket(QString(), QWebSocketProtocol::VersionLatest, this);

    connect(p->ws, &QWebSocket::connected, this, &QNostrRelay::serverConnected);
    connect(p->ws, &QWebSocket::disconnected, this, &QNostrRelay::serverDisonnected);
    connect(p->ws, &QWebSocket::sslErrors, this, &QNostrRelay::sslErrors);
    connect(p->ws, static_cast<void(QWebSocket::*)(QAbstractSocket::SocketError)>(&QWebSocket::error), this, &QNostrRelay::error);
    connect(p->ws, &QWebSocket::textMessageReceived, this, &QNostrRelay::analizeData);
}

QString QNostrRelay::calculateId(const Event &e)
{
    QJsonArray array;
    array << 0;
    array << e.pubkey.value();
    array << (int)e.created_at->toSecsSinceEpoch();
    array << e.kind;
    array << QJsonValue(e.tagsArray());
    array << e.content;

    QJsonDocument json(array);
    return QString::fromUtf8(QCryptographicHash::hash(json.toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex().toLower());
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

QByteArray QNostrRelay::sign(const QByteArray &data, const QByteArray &privateKey)
{
   auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

   secp256k1_keypair keypair;
   auto secret = QByteArray::fromBase64(privateKey);
   if (secp256k1_keypair_create(ctx, &keypair, reinterpret_cast<unsigned char *>(secret.data())) != 1)
   {
       secp256k1_context_destroy(ctx);
       return QByteArray();
   }

   std::vector<unsigned char> signature(64);
   if (secp256k1_schnorrsig_sign32(ctx, signature.data(), reinterpret_cast<const unsigned char *>(data.data()), &keypair, nullptr) != 1)
   {
       secp256k1_context_destroy(ctx);
       return QByteArray();
   }

   secp256k1_context_destroy(ctx);
   return QByteArray(reinterpret_cast<const char*>(signature.data()), signature.size());
}

QByteArray QNostrRelay::compressedPublicKey(const QString &secretKey)
{
    const std::string key = qnostr_privateKeyHeader + secretKey.toStdString() + qnostr_privateKeyFooter;
    auto privateKeyBio = BIO_new_mem_buf(key.c_str(), -1);
    if (!privateKeyBio)
    {
        qDebug() << "Failed to create BIO for private key.";
        return QByteArray();
    }

    auto ecKey = PEM_read_bio_ECPrivateKey(privateKeyBio, nullptr, nullptr, nullptr);
    if (!ecKey)
    {
        qDebug() << "Failed to read private key from BIO.";
        BIO_free(privateKeyBio);
        return QByteArray();
    }

    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    const EC_POINT* point = EC_KEY_get0_public_key(ecKey);

    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::string compressedKey(len, '\0');

    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, (unsigned char*)compressedKey.data(), len, nullptr) != len)
    {
        qDebug() << "Failed to compress public key.";
        return "";
    }

    // Clean up
    EC_KEY_free(ecKey);

    return QByteArray::fromStdString(compressedKey).toBase64();
}

QByteArray QNostrRelay::extractPrivateKey(const QByteArray& base64SecretKey)
{
    // Decode the base64-encoded secret key
    auto decodedKey = QByteArray::fromBase64(base64SecretKey).toStdString();

    // Read the private key from the DER data
    const unsigned char* key_data = reinterpret_cast<const unsigned char*>(decodedKey.c_str());
    auto evp_key = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &key_data, decodedKey.size());

    if (!evp_key)
    {
        qDebug() << "Error reading private key";
        return "";
    }

    // Extract the EC_KEY structure
    auto ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    if (!ec_key)
    {
        qDebug() << "Error getting EC_KEY from EVP_PKEY";
        EVP_PKEY_free(evp_key);
        return "";
    }

    // Extract the private key in its binary form (32 bytes)
    const BIGNUM* private_key_bn = EC_KEY_get0_private_key(ec_key);
    unsigned char private_key_bytes[32];
    int private_key_size = BN_bn2bin(private_key_bn, private_key_bytes);

    // Convert the private key to hex-encoded std::string
    std::string private_key_hex;
    for (int i = 0; i < private_key_size; i++)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", private_key_bytes[i]);
        private_key_hex += hex;
    }

    // Clean up
    EC_KEY_free(ec_key);
    EVP_PKEY_free(evp_key);

    return QByteArray::fromHex(QByteArray::fromStdString(private_key_hex)).toBase64();
}

#pragma GCC diagnostic pop

QJsonArray QNostrRelay::Event::tagsArray() const
{
    QJsonArray res;
    for (const auto &t: tags)
        res << QJsonValue( QJsonArray::fromStringList(t) );

    return res;
}

QString QNostrRelay::Event::serialize() const
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = id.value_or(QString());
    obj[QStringLiteral("pubkey")] = pubkey.value_or(QString());
    obj[QStringLiteral("created_at")] = (int)created_at.value_or(QDateTime()).toSecsSinceEpoch();
    obj[QStringLiteral("kind")] = kind;
    obj[QStringLiteral("tags")] = tagsArray();
    obj[QStringLiteral("content")] = content;
    obj[QStringLiteral("sig")] = sig.value_or(QString());

    QJsonArray res;
    res << QStringLiteral("EVENT");
    res << obj;

    return QString::fromUtf8(QJsonDocument(res).toJson(QJsonDocument::Compact));
}

QNostrRelay::Event QNostrRelay::Event::deserialize(const QJsonObject &obj)
{
    Event e;
    e.id = obj.value(QStringLiteral("id")).toString();
    e.content = obj.value(QStringLiteral("content")).toString();
    e.created_at = QDateTime::fromSecsSinceEpoch(obj.value(QStringLiteral("created_at")).toInt());
    e.kind = obj.value(QStringLiteral("kind")).toInt();
    e.pubkey = obj.value(QStringLiteral("pubkey")).toString();
    e.sig = obj.value(QStringLiteral("sig")).toString();

    for (const auto &t: obj.value(QStringLiteral("sig")).toArray())
    {
        QStringList list;
        for (const auto &o: t.toArray())
            list << o.toString();
        e.tags << list;
    }

    return e;
}

QString QNostrRelay::Request::serialize() const
{
    QJsonObject obj;
    if (!ids.isEmpty())
        obj[QStringLiteral("ids")] = QJsonArray::fromStringList(ids);

    if (!authors.isEmpty())
        obj[QStringLiteral("authors")] = QJsonArray::fromStringList(authors);

    if (!kinds.isEmpty())
    {
        QVariantList list;
        for (auto k: kinds)
            list << k;
        obj[QStringLiteral("kinds")] = QJsonArray::fromVariantList(list);
    }
    if (!e.isEmpty())
        obj[QStringLiteral("#e")] = QJsonArray::fromStringList(e);
    if (!p.isEmpty())
        obj[QStringLiteral("#p")] = QJsonArray::fromStringList(p);

    if (since.has_value())
        obj[QStringLiteral("since")] = (int)since->toSecsSinceEpoch();
    if (until.has_value())
        obj[QStringLiteral("until")] = (int)until->toSecsSinceEpoch();

    obj[QStringLiteral("limit")] = limit;

    QJsonArray res;
    res << QStringLiteral("REQ");
    res << subscriptionId.value_or(QString());
    res << obj;

    return QString::fromUtf8(QJsonDocument(res).toJson(QJsonDocument::Compact));
}

QString QNostrRelay::Close::serialize() const
{
    QJsonArray res;
    res << QStringLiteral("CLOSE");
    res << subscriptionId;

    return QString::fromUtf8(QJsonDocument(res).toJson(QJsonDocument::Compact));
}

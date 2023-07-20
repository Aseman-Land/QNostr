#ifndef QNOSTRRELAY_H
#define QNOSTRRELAY_H

#include <QObject>
#include <QAbstractSocket>
#include <QSslError>
#include <QDateTime>
#include <QUrl>
#include <QJsonArray>

#include <optional>

#include "qtnostr_global.h"

QT_BEGIN_NAMESPACE

class LIBQTNOSTR_CORE_EXPORT QNostrRelay : public QObject
{
    Q_OBJECT
    class Private;
    friend class QNostr;

public:
    struct LIBQTNOSTR_CORE_EXPORT Event {
        std::optional<QString> id;
        std::optional<QString> pubkey;
        std::optional<QDateTime> created_at;
        int kind;

        QList<QStringList> tags;
        QString content;
        std::optional<QString> sig;

        QJsonArray tagsArray() const;
        QString serialize() const;
        static Event deserialize(const QJsonObject &obj);
    };
    struct LIBQTNOSTR_CORE_EXPORT Request {
        std::optional<QString> subscriptionId;

        QStringList ids;
        QStringList authors;
        QList<int> kinds;
        QStringList e;
        QStringList p;
        std::optional<QDateTime> since;
        std::optional<QDateTime> until;
        int limit = 1;

        QString serialize() const;
    };
    struct LIBQTNOSTR_CORE_EXPORT Close {
        QString subscriptionId;

        QString serialize() const;
    };

    QNostrRelay(const QUrl &relay, const QString &secretKey, QObject *parent = nullptr);
    QNostrRelay(const QUrl &relay, const QString &publicKey, const QString &privateKey, QObject *parent = nullptr);
    virtual ~QNostrRelay();

public Q_SLOTS:
    void start();
    void stop();

    QString sendEvent(const QString &content);
    QString sendEvent(Event event, bool prepared = false);
    QString sendRequest(Request request);
    void sendClose(const Close &request);
    void sendClose(const QString &subscriptionId);

Q_SIGNALS:
    void failed(const QString &id, const QString &reason);
    void successfully(const QString &id);
    void error(QAbstractSocket::SocketError error);
    void sslErrors(const QList<QSslError> &errors);
    void newEvent(const QString &subscribeId, const Event &event, bool storedEvent);
    void notice(const QString &msg);
    void syncEventsFinished(const QString &subscribeId);
    void disconnected();
    void connected();

protected:
    static QString calculateId(const Event &event);
    static QByteArray sign(const QByteArray &data, const QByteArray &privateKey);
    static QByteArray compressedPublicKey(const QString &secretKey);
    static QByteArray extractPrivateKey(const QByteArray& base64SecretKey);

    static void prepareEvent(Event &event, const QByteArray &publicKey, const QByteArray &privateKey);

private:
    void serverConnected();
    void serverDisonnected();
    void analizeData(const QString &data);
    void init();

private:
    Private *p;
};

QT_END_NAMESPACE

#endif // QNOSTRRELAY_H

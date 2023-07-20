#ifndef QNOSTR_H
#define QNOSTR_H

#include <QObject>
#include <QAbstractSocket>
#include <QSslError>

#include "qnostrrelay.h"

QT_BEGIN_NAMESPACE

class LIBQTNOSTR_CORE_EXPORT QNostr : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QList<QUrl> relays READ relays WRITE setRelays NOTIFY relaysChanged)
    class Private;

public:
    QNostr(const QString &secretKey, QObject *parent = nullptr);
    QNostr(const QString &publicKey, const QString &privateKey, QObject *parent = nullptr);
    virtual ~QNostr();

    QList<QUrl> relays() const;
    void setRelays(const QList<QUrl> &relays);

public Q_SLOTS:
    void addRelay(const QUrl &url);
    void removeRelay(const QUrl &url);

    QString sendEvent(const QString &content);
    QString sendEvent(QNostrRelay::Event event);
    QString sendRequest(QNostrRelay::Request request);
    void sendClose(const QNostrRelay::Close &request);
    void sendClose(const QString &subscriptionId);

Q_SIGNALS:
    void failed(const QString &id, const QString &reason, const QUrl &sourceRelay);
    void successfully(const QString &id, const QUrl &sourceRelay);
    void error(QAbstractSocket::SocketError error, const QUrl &sourceRelay);
    void sslErrors(const QList<QSslError> &errors, const QUrl &sourceRelay);
    void newEvent(const QString &subscribeId, const QNostrRelay::Event &event, bool storedEvent, const QUrl &sourceRelay);
    void notice(const QString &msg, const QUrl &sourceRelay);
    void syncEventsFinished(const QString &subscribeId, const QUrl &sourceRelay);
    void disconnected(const QUrl &sourceRelay);
    void connected(const QUrl &sourceRelay);
    void relaysChanged();

private:
    Private *p;
};

QT_END_NAMESPACE

#endif // QNOSTR_H

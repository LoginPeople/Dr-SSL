#ifndef SSLHELPER_H
#define SSLHELPER_H

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include <string>
#include <sstream>

#include <QObject>

using namespace std;

class SSLHelper : public QObject
{
    Q_OBJECT

    public:
        SSLHelper();
        SSL_CTX * loadCertificates();
        void testConnection(string hostname, string port = "443");
        void log(string text);
        void log(ostream text);
        void showCAs();
        ~SSLHelper();
        stringstream logger;

    signals:
         void logging();
         void addCA(string title, string text);

    private:
        BIO * bio;
        SSL_CTX * ctx;
        SSL * ssl;

};

#endif // SSLHELPER_H

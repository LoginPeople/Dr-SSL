#ifndef SSLHELPER_H
#define SSLHELPER_H

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include <string>
#include <sstream>
#include <wincrypt.h>

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
        void reloadSSL();
        void loadSSL();
        void exportPFX( PCCERT_CONTEXT  pContext, string name);
        ~SSLHelper();
        stringstream logger;

    signals:
         void logging();
         void addCA(string title, string text);

    public slots:
         void dumpCerts();

    private:
        BIO * bio;
        SSL_CTX * ctx;
        SSL * ssl;

};

#endif // SSLHELPER_H

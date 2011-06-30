#include <QtGui/QApplication>

#include <iostream>
#include <objbase.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "mainwindow.h"


using namespace std;

int main(int argc, char *argv[])
{
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    int result = a.exec();


    CoUninitialize();
    EVP_cleanup();
    return result;
}

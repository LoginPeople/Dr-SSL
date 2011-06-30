#include <QtGui/QApplication>

#include <iostream>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"

#include "mainwindow.h"


using namespace std;

int main(int argc, char *argv[])
{

    cout << "starting" << endl;
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    int result = a.exec();

    //int result = 0;
    EVP_cleanup();
    return result;
}

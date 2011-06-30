#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

#include "openssl/x509_vfy.h"

//#include "openssl/safestack.h"

#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>

/*DWORD WINAPI CertGetPublicKeyLength(
  DWORD dwCertEncodingType,
  PCERT_PUBLIC_KEY_INFO pPublicKey
);*/

#include "sslhelper.h"
#include <stdio.h>
#include <iostream>

#include <sstream>

using namespace std;

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

typedef struct {
   int verbose_mode;
   int verify_depth;
   int always_continue;
   SSLHelper * helper;
 } mydata_t;
 int mydata_index;

SSLHelper::SSLHelper()
{
    ctx = NULL;
    ssl = NULL;
    /*ctx = loadCertificates();
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if(!ctx)
    {
        log( string("loadCertificates: ") + string(ERR_reason_error_string(ERR_get_error())) );
        return;
    }

    ssl = SSL_new(ctx);
    if(!ssl)
    {
        log( string("SSL_new: ") + string(ERR_reason_error_string(ERR_get_error())) );

        return;
    }*/
    //loadSSL();
}

SSLHelper::~SSLHelper()
{
    //SSL_free(ssl);
    //SSL_CTX_free(ctx);
}

void SSLHelper::loadSSL()
{
    cout << "before loadCertificates" << endl;
    ctx = loadCertificates();
    cout << "after loadCertificates" << endl;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    cout << "after set_verify" << endl;
    if(!ctx)
    {
        log( string("loadCertificates: ") + string(ERR_reason_error_string(ERR_get_error())) );
        return;
    }

    ssl = SSL_new(ctx);
    if(!ssl)
    {
        log( string("SSL_new: ") + string(ERR_reason_error_string(ERR_get_error())) );

        return;
    }
}

void SSLHelper::reloadSSL()
{
    cout << "before SSL_free" << endl;
    //if(ssl)
    //    SSL_free(ssl);
    cout << "before SSL_CTX_free" << endl;
    //if(ctx)
    //    SSL_CTX_free(ctx);

    loadSSL();
}

void SSLHelper::testConnection(string host, string port)
{
    log( string("Connecting to ") + host + " on port " + port );

    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        log( "failure to create BIO" );
        return;
    }
    BIO_set_conn_hostname(bio, (char * )host.c_str());
    BIO_set_conn_port(bio, (char *)port.c_str());

    BIO_get_ssl(bio, & ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify_depth(ctx, 10);

    mydata_t mydata;
    mydata_index = SSL_get_ex_new_index(0, (void *)"mydata index", NULL, NULL, NULL);
    mydata.verify_depth = 10;
    mydata.verbose_mode = 1;
    mydata.always_continue = 1;
    mydata.helper = this;
    SSL_set_ex_data(ssl, mydata_index, &mydata);

    log( "trying to connect..." );

    if(BIO_do_connect(bio) <= 0)
    {
        /* Handle failed connection */
        log( string("failure to connect: " ) + string(ERR_reason_error_string(ERR_get_error())) );
        return;
    }
    log( "connected" );

    SSL_accept(ssl);
    if(SSL_get_verify_result(ssl) != X509_V_OK)
    {
        /* Handle the failed verification */
        std::ostringstream oss;
        oss << "unverified connection: " << SSL_get_verify_result(ssl) ;
        log( oss.str() );
    }
    else
       log( "connection verified" );

    BIO_free(bio);

    log( "\n==================================\n" );
}

SSL_CTX * SSLHelper::loadCertificates()
{
    SSL_CTX * ctx = SSL_CTX_new(SSLv23_client_method());

    //int err = 0;
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    HCERTSTORE hCertStore = CertOpenSystemStore(0, L"ROOT");

    if(!hCertStore)
    {
        log( "couldn't open the certificate store" );
        return NULL;
    }

    PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
    while ( pCertContext )
    {
        X509 *cert = d2i_X509(NULL, (const unsigned char **)&pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
        if (X509_STORE_add_cert(store, (X509 *)cert) != 1)
        {
            unsigned long err2;
            string abcd("SSL Error: ");
            err2 = ERR_get_error();
            /* continue if error == certificate already in store */
            if(ERR_GET_REASON(err2) != 101)
            {
                while(err2 != 0) {
                    ostringstream res;
                    res << err2;
                    res << " number=";
                    res << ERR_GET_LIB(err2);
                    res << ", function=";
                    res << ERR_GET_FUNC(err2);
                    res << ", reason code=";
                    res << ERR_GET_REASON(err2);
                    res << "\n";
                    abcd += res.str();
                    err2 = ERR_get_error();
                }
                log( abcd.c_str() );
                return NULL;
            }
        }

        pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
    }

    return ctx;
}

void SSLHelper::log(string text)
{
    logger << text << endl;
    emit(logging());
}

void SSLHelper::log(ostream text)
{
    logger << text << endl;
    emit(logging());
}

void SSLHelper::showCAs()
{
    HCERTSTORE         hStoreHandle = NULL;
    PCCERT_CONTEXT     pCertContext = NULL;
    char                pszNameString[256];

    if (hStoreHandle = CertOpenSystemStore(
         NULL,
         L"ROOT"))
        {
             //log("The store has been opened. \n");
        }
        else
        {
             log("The store was not opened.\n");
        }

    while(pCertContext = CertEnumCertificatesInStore(
          hStoreHandle,
          pCertContext))
    {
        //PCERT_INFO certinfo = pCertContext->pCertInfo;
        if(CertGetNameStringA(
           pCertContext,
           CERT_NAME_SIMPLE_DISPLAY_TYPE,
           0,
           NULL,
           pszNameString,
           256))
        {
            std::ostringstream oss;
            //oss << "Certificate retrieved: " << pszNameString;
            //log( oss.str() );
        }
        string name = pszNameString;
        std::ostringstream oss;
        if(CertGetNameStringA(
           pCertContext,
           CERT_NAME_SIMPLE_DISPLAY_TYPE,
           0x1, //=CERT_NAME_ISSUER_FLAG,
           NULL,
           pszNameString,
           256))
        {
            oss << "Issued by:\t\t" << pszNameString << endl;
            //log( oss.str() );
        }
        //string issuer = "Issued by: ";
        //issuer += pszNameString;
        /*int keylength = CertGetPublicKeyLength(pCertContext->dwCertEncodingType, &pCertContext->pCertInfo->SubjectPublicKeyInfo);
        std::ostringstream oss;
        oss << "key length: " << keylength << endl;*/

        //string result = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId;
        oss << "Signature algorithm:\t" << CertOIDToAlgId( pCertContext->pCertInfo->SignatureAlgorithm.pszObjId ) << endl;

        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        oss << "Not before:\t\t" << stLocal.wDay << "/" << stLocal.wMonth << "/" << stLocal.wYear;
        oss << "  " << stLocal.wHour << ":" << stLocal.wMinute << endl;

        //SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        oss << "Not after:\t\t" << stLocal.wDay << "/" << stLocal.wMonth << "/" << stLocal.wYear;
        oss << "  " << stLocal.wHour << ":" << stLocal.wMinute << endl;

        emit(addCA(name, oss.str()));
    }

    if (!CertCloseStore(
             hStoreHandle,
             0))
    {
        log("Failed CertCloseStore");
    }
}

void SSLHelper::dumpCerts()
{
    HCERTSTORE         hStoreHandle = NULL;
    PCCERT_CONTEXT     pCertContext = NULL;
    char                pszNameString[256];

    if (hStoreHandle = CertOpenSystemStore(
         NULL,
         L"ROOT"))
        {
             //log("The store has been opened. \n");
        }
        else
        {
             log("The store was not opened.\n");
             return;
        }

    while(pCertContext = CertEnumCertificatesInStore(
          hStoreHandle,
          pCertContext))
    {
        if(CertGetNameStringA(
           pCertContext,
           CERT_NAME_SIMPLE_DISPLAY_TYPE,
           0,
           NULL,
           pszNameString,
           256))
        {
            std::ostringstream oss;
        }
        string name = pszNameString;

        exportPFX(pCertContext, name+".der");
    }

    if (!CertCloseStore(
             hStoreHandle,
             0))
    {
        log("Failed CertCloseStore");
    }

    wchar_t path[MAX_PATH];
    GetCurrentDirectory(MAX_PATH,path);


    ShellExecute(NULL, L"explore", path, NULL, NULL, SW_SHOWNORMAL);
}

void SSLHelper::exportPFX( PCCERT_CONTEXT pCertContext,
     string name )
 {
     int rc = NO_ERROR;

     HANDLE hFile = CreateFileA(name.c_str(),
         GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
     if (hFile != INVALID_HANDLE_VALUE) {
         DWORD writtenBytes = 0;
         if (WriteFile(hFile, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, &writtenBytes, NULL)) {
             cout << "Written to a pfx file" << endl;
             //OK
         } else {
             rc = GetLastError();
         }
         CloseHandle(hFile);
     } else {
         cout <<"Failed to open the file " << name << endl;
         rc = GetLastError();
     }
 }


static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
   char    buf[256];
   char    issuer[256];
   X509   *err_cert;
   int     err, depth;
   SSL    *ssl;
   mydata_t *mydata;

   err_cert = X509_STORE_CTX_get_current_cert(ctx);
   err = X509_STORE_CTX_get_error(ctx);
   depth = X509_STORE_CTX_get_error_depth(ctx);

   /*
    * Retrieve the pointer to the SSL of the connection currently treated
    * and the application specific data stored into the SSL object.
    */
   ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
   mydata = (mydata_t *)SSL_get_ex_data(ssl, mydata_index);

   X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
   X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, 256);

   /*
    * Catch a too long certificate chain. The depth limit set using
    * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
    * that whenever the "depth>verify_depth" condition is met, we
    * have violated the limit and want to log this error condition.
    * We must do it here, because the CHAIN_TOO_LONG error would not
    * be found explicitly; only errors introduced by cutting off the
    * additional certificates would be logged.
    */
   if (depth > mydata->verify_depth) {
       preverify_ok = 0;
       err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
       X509_STORE_CTX_set_error(ctx, err);
   }
   if (!preverify_ok) {
       //printf("verify error:num=%d:%s:depth=%d:%s\n", err,
       //         X509_verify_cert_error_string(err), depth, buf);
       std::ostringstream oss;
       oss << "verify error:num=" << err << ":" << X509_verify_cert_error_string(err) << endl;
       oss << "depth=" << depth << ":" << endl;
       oss << "\t-> subject:   "<< buf << endl;
       oss << "\t-> issued by: " << issuer << endl;
       mydata->helper->log( oss.str() );
   }
   else if (mydata->verbose_mode)
   {
       std::ostringstream oss;
       oss << "depth=" << depth << ":" << endl;
       oss << "\t-> subject:   "<< buf << endl;
       oss << "\t-> issued by: " << issuer << endl;
       mydata->helper->log( oss.str() );
       //mydata->helper->log( string("depth=") + string(depth) + string(":") + string(buf) );
   }

   /*
    * At this point, err contains the last verification error. We can use
    * it for something special
    */
   if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT))
   {
     X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
     //printf("issuer= %s\n", buf);
     std::ostringstream oss;
     oss << "issuer = " << buf;
     mydata->helper->log( oss.str() );
     //mydata->helper->log( string("issuer = ") + string(buf) );
   }

   if (mydata->always_continue)
     return 1;
   else
     return preverify_ok;
}

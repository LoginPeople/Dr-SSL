#ifndef SSLEXCEPTION_H
#define SSLEXCEPTION_H

#include <stdexcept>
#include <string>

class SSLException : public std::runtime_error
{
public:
    SSLException(const std::string& message = "SSL Exception") : std::runtime_error(message) { }
};

class CertificateException : public SSLException
{
public:
    CertificateException(const std::string& message = "Certificate Exception") : SSLException(message) { }
};

class ConnectionException : public SSLException
{
public:
    ConnectionException(const std::string& message = "Connection Exception") : SSLException(message) { }
};
#endif // SSLEXCEPTION_H

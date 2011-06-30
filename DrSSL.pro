#-------------------------------------------------
#
# Project created by QtCreator 2011-06-28T08:43:06
#
#-------------------------------------------------

QT       += core gui

TARGET = DrSSL
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    sslhelper.cpp

HEADERS  += mainwindow.h \
    sslhelper.h

FORMS    += mainwindow.ui

CONFIG += console

INCLUDEPATH += C:\OpenSSL\include
LIBS += -LC:\OpenSSL\lib -lssleay32 -llibeay32 -lcrypt32 -lole32

RESOURCES += \
    pics.qrc

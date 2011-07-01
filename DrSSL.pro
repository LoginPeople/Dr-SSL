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
    sslhelper.cpp \
    dropqtoolbox.cpp

HEADERS  += mainwindow.h \
    sslhelper.h \
    dropqtoolbox.h

FORMS    += mainwindow.ui

#CONFIG += console

INCLUDEPATH += C:\OpenSSL\include
LIBS += -LC:\OpenSSL\lib -lssleay32 -llibeay32 -lshlwapi -lcrypt32 -lole32 -lshell32

RESOURCES += \
    pics.qrc

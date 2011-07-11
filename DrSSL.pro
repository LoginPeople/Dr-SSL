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
    dropqtoolbox.h \
    sslexception.h

FORMS    += mainwindow.ui

#CONFIG += console

INCLUDEPATH += C:\OpenSSL\include
LIBS += -LC:\OpenSSL\lib -lssleay32 -llibeay32 -lshlwapi -lcrypt32 -lole32 -lshell32

RESOURCES += \
    pics.qrc

OTHER_FILES += \
    logo_loginPeople.png \
    dr_sso_32.ico \
    DrSSL.manifest

win32 {
    WINSDK_DIR = C:/Program\ Files/Microsoft\ SDKs/Windows/v6.0A
    WIN_PWD = $$replace(PWD, /, \\)
    OUT_PWD_WIN = $$replace(OUT_PWD, /, \\)
    QMAKE_POST_LINK = "$$WINSDK_DIR/bin/mt.exe -manifest $$quote($$WIN_PWD\\$$basename(TARGET).manifest) -outputresource:$$quote($$OUT_PWD_WIN\\${DESTDIR_TARGET};1)"
}

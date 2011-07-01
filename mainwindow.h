#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "sslhelper.h"

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void startDiagnosis();
    void addLog();
    void addToolboxItem(string title, string text);
    void refreshCAs();
    void clearLog();
    void addCert(string);
    void verified(bool);

private:
    Ui::MainWindow *ui;
    SSLHelper      *ssl;
    void removeWidgetsFromToolBox();
};

#endif // MAINWINDOW_H

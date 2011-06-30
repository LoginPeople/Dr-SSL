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

private:
    Ui::MainWindow *ui;
    SSLHelper      *ssl;
};

#endif // MAINWINDOW_H

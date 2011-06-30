#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sslhelper.h"
#include <iostream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    ssl(new SSLHelper)
{
    ui->setupUi(this);
    connect(ui->pushButton, SIGNAL( clicked() ), this, SLOT(startDiagnosis()));
    connect(ssl, SIGNAL(logging()), this, SLOT(addLog()));
}

MainWindow::~MainWindow()
{
    delete ssl;
    delete ui;
}

void MainWindow::startDiagnosis()
{
    ui->errorbox->clear();
    if(ui->host->text() == "" || ui->port->text() == "")
    {
        ui->errorbox->setText("Please fill in hostname and port");
    }

    cout << "connecting to: " << ui->host->text().toStdString() << ":" << ui->port->text().toStdString() << endl;

    ssl->testConnection(ui->host->text().toStdString(), ui->port->text().toStdString());
}

void MainWindow::addLog()
{
    //cout << "LOG CALLED" << endl;
    ui->log->appendPlainText( QString::fromStdString(ssl->logger.str()) );
    ssl->logger.str("");
}

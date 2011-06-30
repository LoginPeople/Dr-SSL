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
    connect(ui->refreshButton, SIGNAL( clicked() ), this, SLOT(refreshCAs()));
    connect(ssl, SIGNAL(addCA(string,string)), this, SLOT(addToolboxItem(string,string)));
    connect(ui->dumpcertsButton, SIGNAL( clicked()), ssl, SLOT(dumpCerts()));
    refreshCAs();
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
    ui->log->appendPlainText( QString::fromStdString(ssl->logger.str()) );
    ssl->logger.str("");
}

void MainWindow::addToolboxItem(string title, string text)
{
    QLabel *label = new QLabel(QString::fromStdString(text),this);

    ui->toolBox->addItem(label,QString::fromStdString(title));
}

void MainWindow::refreshCAs()
{
    cout << "in refreshCAs" << endl;
    removeWidgetsFromToolBox();
    cout << "before reloadSSL" << endl;
    ssl->reloadSSL();
    cout << "after reloadSSL" << endl;
    ssl->showCAs();
    cout << "after showCAs" << endl;
}

void MainWindow::removeWidgetsFromToolBox()
{
    cout << "before removing widget" << endl;
    while(ui->toolBox->count() != 0)
    {
        cout << "removing widget" << endl;
        QWidget * widg = ui->toolBox->widget(0);
        ui->toolBox->removeItem(0);
        delete widg;
    }
    cout << "after removing widget" << endl;
}

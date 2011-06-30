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

void MainWindow::addToolboxItem(string title, string text)
{
    cout << "addToolboxItem called" << endl;
    QLabel *label = new QLabel(QString::fromStdString(text),this);
    //QLabel *label2 = new QLabel("Nokia E51",this);
    //QLabel *label3 = new QLabel("Nokia 5800 XM",this);

    cout << " added item at " << ui->toolBox->addItem(label,QString::fromStdString(title)) << endl;
    //cout << "second item at " << ui->toolBox->addItem(label2,"Nokia E-Series") << endl;
    //cout << " third item at " << ui->toolBox->addItem(label3,"Xpress music") << endl;
    cout << "end of addToolboxItem" << endl;
}

void MainWindow::refreshCAs()
{
    cout << "refreshCAs called" << endl;
    removeWidgetsFromToolBox();
    ssl->showCAs();
    //addToolboxItem("abc", "def");
    //addToolboxItem("ghi", "jkl");
    //addToolboxItem("mno", "pqr");
}

void MainWindow::removeWidgetsFromToolBox()
{
    while(ui->toolBox->count() != 0)
    {
        cout << "removing item n°" << 0 << endl;
        QWidget * widg = ui->toolBox->widget(0);
        ui->toolBox->removeItem(0);
        delete widg;
    }
}

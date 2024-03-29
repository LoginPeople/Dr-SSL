
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "sslhelper.h"
#include <iostream>
#include <shellapi.h>
#include "sslexception.h"

#define SUPPORT_EMAIL "support@loginpeople.com"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    ssl(new SSLHelper)
{
    setAcceptDrops(true);
    ui->setupUi(this);
    connect(ui->pushButton, SIGNAL( clicked() ), this, SLOT(startDiagnosis()));
    connect(ssl, SIGNAL(logging()), this, SLOT(addLog()));
    connect(ui->refreshButton, SIGNAL( clicked() ), this, SLOT(refreshCAs()));
    connect(ssl, SIGNAL(addCA(string,string)), this, SLOT(addToolboxItem(string,string)));
    connect(ui->dumpcertsButton, SIGNAL( clicked()), this, SLOT(dumpCerts()));
    connect(ui->clearlogButton, SIGNAL( clicked()), this, SLOT(clearLog()));
    refreshCAs();
    ui->toolBox->setAcceptDrops(true);
    connect(ui->toolBox, SIGNAL(dropCert(string)), this, SLOT(addCert(string)));
    connect(ssl, SIGNAL(verifiedStatus(bool)), this, SLOT(verified(bool)));
    connect(ui->sendLog, SIGNAL(clicked()), this, SLOT(emailLog()));
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

    try {
        ssl->testConnection(ui->host->text().toStdString(), ui->port->text().toStdString());
    }
    catch(ConnectionException& e) {
        ui->errorbox->setText(e.what());
    }
}

void MainWindow::addLog()
{
    ui->log->appendPlainText( QString::fromStdString(ssl->logger.str()) );
    ssl->logger.str("");
}

void MainWindow::addToolboxItem(string title, string text)
{
    QLabel *label = new QLabel(QString::fromStdString(text),this);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse);

    ui->toolBox->addItem(label,QString::fromStdString(title));
}

void MainWindow::refreshCAs()
{
    cout << "in refreshCAs" << endl;
    removeWidgetsFromToolBox();
    try {
        cout << "before reloadSSL" << endl;
        ssl->reloadSSL();
        cout << "after reloadSSL" << endl;
        ssl->showCAs();
        cout << "after showCAs" << endl;
    }
    catch(CertificateException& e) {
        ui->errorbox->setText(e.what());
    }
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

void MainWindow::clearLog()
{
    cout << "clearing the log" << endl;
    ui->log->clear();
}

void MainWindow::addCert(string url)
{
    try {
        ssl->addCert(url);
        refreshCAs();
    }
    catch(CertificateException& e) {
        ui->errorbox->setText(e.what());
    }
}

void MainWindow::verified(bool verified)
{
    if(verified)
    {
        ui->connectionStatus->setStyleSheet("* { background-color: green; color: white; font-weight: bold }");
        ui->connectionStatus->setText("Verified connection");
    }
    else
    {
        ui->connectionStatus->setStyleSheet("* { background-color: red; color: white; font-weight: bold }");
        ui->connectionStatus->setText("Unverified connection");
    }
}

void MainWindow::emailLog()
{
    string mail = "mailto:" SUPPORT_EMAIL "?Subject= DrSSL report&Body=";
    QString msg = ui->log->toPlainText();
    msg.replace(QChar('\n'), tr("%0A"));
    mail += msg.toStdString();

    ShellExecuteA(0,"open",mail.c_str(),"","",1);
}

void MainWindow::dumpCerts()
{
    try{
        ssl->dumpCerts();
    }
    catch(CertificateException& e)
    {
        ui->errorbox->setText(e.what());
    }
}

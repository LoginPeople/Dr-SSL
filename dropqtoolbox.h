#ifndef DROPQTOOLBOX_H
#define DROPQTOOLBOX_H

#include <QToolBox>
#include <QDragEnterEvent>

#include <string>
using namespace std;

class DropQToolBox : public QToolBox
{
    Q_OBJECT
public:
    explicit DropQToolBox(QWidget *parent = 0);
    void dropEvent(QDropEvent *event);
    void dragEnterEvent(QDragEnterEvent *event);

signals:
    void dropCert(string);

public slots:

};

#endif // DROPQTOOLBOX_H

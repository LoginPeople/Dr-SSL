#include "dropqtoolbox.h"
#include <iostream>
#include <QUrl>

using namespace std;

DropQToolBox::DropQToolBox(QWidget *parent) :
    QToolBox(parent)
{
    setAcceptDrops(true);
}

void DropQToolBox::dropEvent(QDropEvent *event)
{
    QList<QUrl> urlList;

    if (event->mimeData()->hasUrls())
    {
        urlList = event->mimeData()->urls();

        if ( urlList.size() > 0)
        {
            cout << "url: " << urlList.first().toString().toStdString() << endl;
            emit(dropCert(urlList.first().toString().toStdString()));
        }
    }
    event->acceptProposedAction();
}

void DropQToolBox::dragEnterEvent(QDragEnterEvent *event)
{
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

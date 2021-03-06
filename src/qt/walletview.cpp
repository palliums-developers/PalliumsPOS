// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/balancesdialog.h>
#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/sendmpdialog.h>
#include <qt/lookupspdialog.h>
#include <qt/lookuptxdialog.h>
#include <qt/lookupaddressdialog.h>
#include <qt/metadexcanceldialog.h>
#include <qt/metadexdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/tradehistorydialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/txhistorydialog.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <ui_interface.h>

#include <QAction>
#include <QActionGroup>
#include <QDebug>
#include <QDialog>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QProgressDialog>
#include <QPushButton>
#include <QTableView>
#include <QVBoxLayout>

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    platformStyle(_platformStyle)
{
    // Create tabs
    overviewPage = new OverviewPage(platformStyle);

    // Transactions page, Omni transactions in first tab, BTC only transactions in second tab
    transactionsPage = new QWidget(this);
    bitcoinTXTab = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    bitcoinTXTab->setLayout(vbox);
    mpTXTab = new TXHistoryDialog;
    transactionsPage = new QWidget(this);
    QVBoxLayout *txvbox = new QVBoxLayout();
    txTabHolder = new QTabWidget();
    txTabHolder->addTab(mpTXTab,tr("Omni Layer"));
    txTabHolder->addTab(bitcoinTXTab,tr("Bitcoin"));
    txvbox->addWidget(txTabHolder);
    transactionsPage->setLayout(txvbox);

    balancesPage = new BalancesDialog();

    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);

    // sending page
    sendCoinsPage = new QWidget(this);
    QVBoxLayout *svbox = new QVBoxLayout();
    sendCoinsTab = new SendCoinsDialog(platformStyle);
    sendMPTab = new SendMPDialog(platformStyle);
    sendTabHolder = new QTabWidget();
    sendTabHolder->addTab(sendMPTab,tr("Omni Layer"));
    sendTabHolder->addTab(sendCoinsTab,tr("Bitcoin"));
    svbox->addWidget(sendTabHolder);
    sendCoinsPage->setLayout(svbox);

    /**
     * exchange page is disabled in this version
     *
    exchangePage = new QWidget(this);
    QVBoxLayout *exvbox = new QVBoxLayout();
    metaDExTab = new MetaDExDialog();
    cancelTab = new MetaDExCancelDialog();
    QTabWidget *exTabHolder = new QTabWidget();
    tradeHistoryTab = new TradeHistoryDialog;
    // exTabHolder->addTab(new QWidget(),tr("Trade Bitcoin/Mastercoin")); not yet implemented
    exTabHolder->addTab(metaDExTab,tr("Trade Omni Layer Properties"));
    exTabHolder->addTab(tradeHistoryTab,tr("Trade History"));
    exTabHolder->addTab(cancelTab,tr("Cancel Orders"));
    exvbox->addWidget(exTabHolder);
    exchangePage->setLayout(exvbox);
    **/

    // toolbox page
    toolboxPage = new QWidget(this);
    QVBoxLayout *tvbox = new QVBoxLayout();
    addressLookupTab = new LookupAddressDialog();
    spLookupTab = new LookupSPDialog();
    txLookupTab = new LookupTXDialog();
    QTabWidget *tTabHolder = new QTabWidget();
    tTabHolder->addTab(addressLookupTab,tr("Lookup Address"));
    tTabHolder->addTab(spLookupTab,tr("Lookup Property"));
    tTabHolder->addTab(txLookupTab,tr("Lookup Transaction"));
    tvbox->addWidget(tTabHolder);
    toolboxPage->setLayout(tvbox);

    addWidget(overviewPage);
    addWidget(balancesPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
    // addWidget(exchangePage);
    addWidget(toolboxPage);

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));
    connect(overviewPage, SIGNAL(omniTransactionClicked(uint256)), mpTXTab, SLOT(focusTransaction(uint256)));
    connect(overviewPage, SIGNAL(outOfSyncWarningClicked()), this, SLOT(requestedSyncWarningInfo()));

    // Highlight transaction after send
    connect(sendCoinsPage, SIGNAL(coinsSent(uint256)), transactionView, SLOT(focusTransaction(uint256)));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, SIGNAL(clicked()), transactionView, SLOT(exportClicked()));

    // Pass through messages from sendCoinsTab
    connect(sendCoinsTab, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    // Pass through messages from transactionView
    connect(transactionView, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
}

WalletView::~WalletView()
{
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to either Omni/Bitcoin history page
        connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), gui, SLOT(gotoHistoryPage()));
        connect(overviewPage, SIGNAL(omniTransactionClicked(uint256)), gui, SLOT(gotoOmniHistoryTab()));

        // Navigate to transaction history page after send
        connect(sendCoinsPage, SIGNAL(coinsSent(uint256)), gui, SLOT(gotoHistoryPage()));

        // Receive and report messages
        connect(this, SIGNAL(message(QString,QString,unsigned int)), gui, SLOT(message(QString,QString,unsigned int)));

        // Pass through encryption status changed signals
        connect(this, SIGNAL(encryptionStatusChanged()), gui, SLOT(updateWalletStatus()));

        // Pass through transaction notifications
        connect(this, SIGNAL(incomingTransaction(QString,int,CAmount,QString,QString,QString,QString)), gui, SLOT(incomingTransaction(QString,int,CAmount,QString,QString,QString,QString)));

        // Connect HD enabled state signal
        connect(this, SIGNAL(hdEnabledStatusChanged()), gui, SLOT(updateWalletStatus()));
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    balancesPage->setClientModel(clientModel);
    sendMPTab->setClientModel(clientModel);
    mpTXTab->setClientModel(clientModel);
    // cancelTab->setClientModel(clientModel);
    // tradeHistoryTab->setClientModel(clientModel);
    // metaDExTab->setClientModel(clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    transactionView->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);
    usedSendingAddressesPage->setModel(_walletModel ? _walletModel->getAddressTableModel() : nullptr);
    sendCoinsTab->setModel(walletModel);
    sendMPTab->setWalletModel(walletModel);
    balancesPage->setWalletModel(walletModel);
    mpTXTab->setWalletModel(walletModel);
    // metaDExTab->setWalletModel(walletModel);
    // tradeHistoryTab->setWalletModel(walletModel);
    // cancelTab->setWalletModel(walletModel);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));

        // Handle changes in encryption status
        connect(_walletModel, SIGNAL(encryptionStatusChanged()), this, SIGNAL(encryptionStatusChanged()));
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged();

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(processNewTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(_walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));

        // Show progress dialog
        connect(_walletModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->node().isInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, walletModel->getWalletName());
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoBalancesPage()
{
    setCurrentWidget(balancesPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoBitcoinHistoryTab()
{
    setCurrentWidget(transactionsPage);
    txTabHolder->setCurrentIndex(1);
}

void WalletView::gotoOmniHistoryTab()
{
    setCurrentWidget(transactionsPage);
    txTabHolder->setCurrentIndex(0);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoExchangePage()
{
    setCurrentWidget(exchangePage);
}

void WalletView::gotoToolboxPage()
{
    setCurrentWidget(toolboxPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsTab->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    sendTabHolder->setCurrentIndex(1);
    return sendCoinsTab->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged();
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    usedSendingAddressesPage->show();
    usedSendingAddressesPage->raise();
    usedSendingAddressesPage->activateWindow();
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    usedReceivingAddressesPage->show();
    usedReceivingAddressesPage->raise();
    usedReceivingAddressesPage->activateWindow();
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
        progressDialog->setCancelButtonText(tr("Cancel"));
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}

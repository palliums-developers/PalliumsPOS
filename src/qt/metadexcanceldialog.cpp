// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "metadexcanceldialog.h"
#include "ui_metadexcanceldialog.h"

#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "coincontroldialog.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "clientmodel.h"
#include "wallet.h"
#include "base58.h"
#include "coincontrol.h"
#include "ui_interface.h"

#include <boost/filesystem.hpp>

#include "leveldb/db.h"
#include "leveldb/write_batch.h"

// potentially overzealous includes here
#include "base58.h"
#include "rpcserver.h"
#include "init.h"
#include "util.h"
#include <fstream>
#include <algorithm>
#include <vector>
#include <utility>
#include <string>
#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/find.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"
// end potentially overzealous includes
using namespace json_spirit; // since now using Array in mastercore.h this needs to come first

#include "mastercore.h"
using namespace mastercore;

// potentially overzealous using here
using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace leveldb;
// end potentially overzealous using

#include "mastercore_dex.h"
#include "mastercore_parse_string.h"
#include "mastercore_tx.h"
#include "mastercore_sp.h"

#include <QDateTime>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>

MetaDExCancelDialog::MetaDExCancelDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MetaDExCancelDialog),
    clientModel(0)
{
    ui->setupUi(this);

    connect(ui->radioCancelPair, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));
    connect(ui->radioCancelPrice, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));
    connect(ui->radioCancelEverything, SIGNAL(clicked()),this, SLOT(UpdateCancelCombo()));

    // perform initial from address population
    UpdateAddressSelector();
}


/**
 * Sets the client model.
 *
 * Note: for metadex cancels we only need to know when the Omni state has been refreshed
 * so only the client model (instead of both client and wallet models) is needed.
 */
void MetaDExCancelDialog::setClientModel(ClientModel *model)
{
    if (model != NULL) {
        this->clientModel = model;
        connect(model, SIGNAL(refreshOmniState()), this, SLOT(RefreshUI()));
    }
}

/**
 * Refreshes the cancellation address selector
 *
 * Note: only addresses that have a currently open MetaDEx trade (determined by
 * the metadex map) will be shown in the address selector (cancellations sent from
 * addresses without an open MetaDEx trade are invalid).
 */
void MetaDExCancelDialog::UpdateAddressSelector()
{
    for (md_PropertiesMap::iterator my_it = metadex.begin(); my_it != metadex.end(); ++my_it) {
        md_PricesMap & prices = my_it->second;
        for (md_PricesMap::iterator it = prices.begin(); it != prices.end(); ++it) {
            md_Set & indexes = (it->second);
            for (md_Set::iterator it = indexes.begin(); it != indexes.end(); ++it) {
                CMPMetaDEx obj = *it;
                if(IsMyAddress(obj.getAddr())) { // this address is ours and has an active MetaDEx trade
                    int idx = ui->fromCombo->findText(QString::fromStdString(obj.getAddr())); // avoid adding duplicates
                    if (idx == -1) ui->fromCombo->addItem(QString::fromStdString(obj.getAddr()));
                }
            }
        }
    }
}

/**
 * Refreshes the cancel combo with the latest data based on the currently selected
 * radio button.
 */
void MetaDExCancelDialog::UpdateCancelCombo()
{
    string senderAddress = ui->fromCombo->currentText().toStdString();
    QString existingSelection = ui->cancelCombo->currentText();

    if (senderAddress.empty()) {
        return; // no sender address selected, likely no wallet addresses have open MetaDEx trades
    }

    if ((!ui->radioCancelPair->isChecked()) && (!ui->radioCancelPrice->isChecked()) && (!ui->radioCancelEverything->isChecked())) {
        return; // no radio button is selected
    }

    if (ui->radioCancelEverything->isChecked()) {
        ui->cancelCombo->clear();
        ui->cancelCombo->addItem("All currently active sell orders","ALL");
        return; // don't waste time on work we don't need to do for this case
    }

    ui->cancelCombo->clear();
    for (md_PropertiesMap::iterator my_it = metadex.begin(); my_it != metadex.end(); ++my_it) {
        md_PricesMap & prices = my_it->second;
        for (md_PricesMap::iterator it = prices.begin(); it != prices.end(); ++it) {
            XDOUBLE price = it->first;
            md_Set & indexes = it->second;
            for (md_Set::iterator it = indexes.begin(); it != indexes.end(); ++it) {
                CMPMetaDEx obj = *it;
                if(senderAddress == obj.getAddr()) {
                    bool isBuy = false; // sell or buy? (from UI perspective)
                    bool divisible;
                    if ((obj.getProperty() == OMNI_PROPERTY_MSC) || (obj.getProperty() == OMNI_PROPERTY_TMSC)) isBuy = true;
                    string sellToken = getPropertyName(obj.getProperty()).c_str();
                    string desiredToken = getPropertyName(obj.getDesProperty()).c_str();
                    string sellId = static_cast<ostringstream*>( &(ostringstream() << obj.getProperty()) )->str();
                    string desiredId = static_cast<ostringstream*>( &(ostringstream() << obj.getDesProperty()) )->str();
                    if(sellToken.size()>30) sellToken=sellToken.substr(0,30)+"...";
                    sellToken += " (#" + sellId + ")";
                    if(desiredToken.size()>30) desiredToken=desiredToken.substr(0,30)+"...";
                    desiredToken += " (#" + desiredId + ")";
                    string comboStr = "Cancel all orders ";
                    if (isBuy) {
                        comboStr += "buying " + desiredToken;
                        divisible = isPropertyDivisible(obj.getDesProperty());
                    } else {
                        comboStr += "selling " + sellToken;
                        divisible = isPropertyDivisible(obj.getProperty());
                    }
                    string dataStr = sellId + "/" + desiredId;
                    if (ui->radioCancelPrice->isChecked()) { // append price if needed
                        if (isBuy) {
                            if (!divisible) price = price/COIN;
                        } else {
                            if (!divisible) { price = obj.effectivePrice()/COIN; } else { price = obj.effectivePrice(); }
                        }
                        comboStr += " priced at " + StripTrailingZeros(price.str(16, std::ios_base::fixed)); // limited to 16 digits of precision for display purposes
                        if ((obj.getProperty() == OMNI_PROPERTY_MSC) || (obj.getDesProperty() == OMNI_PROPERTY_MSC)) { comboStr += " MSC/SPT"; } else { comboStr += " TMSC/SPT"; }
                        dataStr += ":" + price.str(DISPLAY_PRECISION_LEN, std::ios_base::fixed);
                    }
                    int index = ui->cancelCombo->findText(QString::fromStdString(comboStr));
                    if ( index == -1 ) { ui->cancelCombo->addItem(QString::fromStdString(comboStr),QString::fromStdString(dataStr)); }
                }
            }
        }
    }
    int idx = ui->cancelCombo->findText(existingSelection, Qt::MatchExactly);
    if (idx != -1) ui->cancelCombo->setCurrentIndex(idx); // if value selected before update and it still exists, reselect it

}

/**
 * Refreshes the UI fields with the most current data - called when the
 * refreshOmniState() signal is received.
 */
void MetaDExCancelDialog::RefreshUI()
{
    UpdateAddressSelector();
    UpdateCancelCombo();
}

void MetaDExCancelDialog::sendCancelTransaction()
{
    // TODO - implement creation of cancels
}


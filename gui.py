#!/usr/bin/env python
#
# Copyright (C) 2017 Andrew Chow

import util

import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLineEdit, QMessageBox, QInputDialog, QGroupBox, QHBoxLayout, QVBoxLayout, QGridLayout, QLabel
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, Qt
 
class App(QWidget):
 
    def __init__(self):
        super().__init__()
        self.title = 'Bitcoin Payment Protocol Interface'
        self.left = 10
        self.top = 10
        self.width = 700
        self.height = 500
        self.initUI()
 
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.uri_box = QLineEdit(self)
        go_button = QPushButton('Go!', self)
        go_button.clicked.connect(self.handle_entered_uri)
        
        self.main_box = QGroupBox("Bitcoin Payment Protocol Interface")
        main_layout = QGridLayout()
        main_layout.addWidget(QLabel("Bitcoin URI:"), 0, 0)
        main_layout.addWidget(self.uri_box, 0, 1)
        main_layout.addWidget(go_button, 0, 2)
        
        self.payment_data_box = QGroupBox()
        main_layout.addWidget(self.payment_data_box, 1, 1)
        
        self.main_box.setLayout(main_layout)
        
        windowLayout = QVBoxLayout()
        windowLayout.addWidget(self.main_box)
        self.setLayout(windowLayout)

        self.show()
    
    def display_pr(self, pr):
        if pr.error:
            print(pr.error)
            exit()
        else:
            pr.verify()
            self.payment_data_box.setTitle("Payment Request Data")
            pr_data_layout = QGridLayout()

            pr_data_layout.addWidget(QLabel("Network:"), 0, 0)
            network_lbl = QLabel(pr.details.network)
            network_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(network_lbl, 0, 1)

            pr_data_layout.addWidget(QLabel("Requestor:"), 1, 0)
            requestor_lbl = QLabel(pr.get_requestor())
            requestor_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(requestor_lbl, 1, 1)

            pr_data_layout.addWidget(QLabel("Memo:"), 2, 0)
            memo_lbl = QLabel(pr.get_memo())
            memo_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(memo_lbl, 2, 1)

            pr_data_layout.addWidget(QLabel("Expiration:"), 3, 0)
            expire_lbl = QLabel(util.format_time(pr.get_expiration_date()))
            expire_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(expire_lbl, 3, 1)

            pr_data_layout.addWidget(QLabel("Creation Time:"), 4, 0)
            creation_lbl = QLabel(util.format_time(pr.details.time))
            creation_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(creation_lbl, 4, 1)

            pr_data_layout.addWidget(QLabel("Verification status:"), 5, 0)
            verification_lbl = QLabel(pr.get_verify_status())
            verification_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(verification_lbl, 5, 1)

            pr_data_layout.addWidget(QLabel("Merchant Data:"), 6, 0)
            merch_lbl = QLabel(str(pr.details.merchant_data))
            merch_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            pr_data_layout.addWidget(merch_lbl, 6, 1)

            pr_data_layout.addWidget(QLabel("Outputs:"), 7, 0)
            i = 0
            for out in pr.get_outputs():
                type_lbl = QLabel()
                if out[0] == util.TYPE_ADDRESS:
                    pr_data_layout.addWidget(QLabel("  Type:"), 8 + i, 0)
                    type_lbl.setText("Address")
                    pr_data_layout.addWidget(QLabel("  Address:"), 8 + i + 1, 0)
                elif out[0] == util.TYPE_PUBKEY:
                    pr_data_layout.addWidget(QLabel("  Type:"), 8 + i, 0)
                    type_lbl.setText("Public Key")
                    pr_data_layout.addWidget(QLabel("  Public Key:"), 8 + i + 1, 0)
                elif out[0] == util.TYPE_SCRIPT:
                    pr_data_layout.addWidget(QLabel("  Type:"), 8 + i, 0)
                    type_lbl.setText("Script")
                    pr_data_layout.addWidget(QLabel("  Script:"), 8 + i + 1, 0)
                else:
                    pr_data_layout.addWidget(QLabel("  Type:"), 8 + i, 0)
                    type_lbl.setText("Unknown")
                    pr_data_layout.addWidget(QLabel("  Data:"), 8 + i + 1, 0)

                type_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                pr_data_layout.addWidget(type_lbl, 8 + i, 1)

                data_lbl = QLabel(out[1])
                data_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                pr_data_layout.addWidget(data_lbl, 8 + i + 1, 1)

                amt_lbl = QLabel(util.format_satoshis(out[2]) + " BTC")
                amt_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
                pr_data_layout.addWidget(QLabel("  Amount:"), 8 + i + 2, 0)
                pr_data_layout.addWidget(amt_lbl, 8 + i + 2, 1)

                i += 3
            next_button = QPushButton("Next")
            next_button.clicked.connect(self.make_further_instructions(pr))
            pr_data_layout.addWidget(next_button, 8 + i, 0)
            self.payment_data_box.setLayout(pr_data_layout)
    
    @pyqtSlot()
    def handle_entered_uri(self):
        uri = self.uri_box.text().strip()
        util.parse_URI(uri, self.display_pr)
    
    def make_further_instructions(self, pr):
        def further_instructions():
            response = QMessageBox.information(self, "Next Step", "To continue, send the necessary amounts of Bitcoin to the addresses specified in the 'Outputs' field above. Once broadcast, press Yes to Continue or Cancel to quit.", QMessageBox.Cancel | QMessageBox.Yes, QMessageBox.Cancel)
            if response == QMessageBox.Cancel:
                sys.exit()
            elif response == QMessageBox.Yes:
                if pr.details.payment_url:
                    raw_tx, okPressed1 = QInputDialog.getText(self, "Enter Raw Transaction","Enter the hex of the transaction that was just made:", QLineEdit.Normal, "")
                    if okPressed1 and raw_tx != '':
                        ref_addr, okPressed2 = QInputDialog.getText(self, "Enter Refund Address","Enter a refund address:", QLineEdit.Normal, "")
                        if okPressed2 and ref_addr != '':
                            try:
                                result = pr.send_ack(raw_tx.strip(), ref_addr.strip())
                                if result[0]:
                                    QMessageBox.information(self, "Complete!", "Payment request successful: " + result[1] + "\n\nClick Ok to exit", QMessageBox.Ok, QMessageBox.Ok)
                                    sys.exit()
                                else:
                                    QMessageBox.error(self, "Error!", "Payment request was not successful: " + result[1] + "\n\nClick Ok to exit", QMessageBox.Ok, QMessageBox.Ok)
                                    sys.exit()
                            except:
                                QMessageBox.error(self, "Error!", "There was an error parsing the raw transaction or address. Please restart and try again.\n\nClick Ok to exit", QMessageBox.Ok, QMessageBox.Ok)
                                sys.exit()
                                
        return further_instructions
 
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())

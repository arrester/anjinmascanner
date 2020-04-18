import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QMainWindow, QHBoxLayout, QVBoxLayout, QMessageBox, QLabel, QLineEdit, QTextBrowser, QGridLayout, QTextEdit, QDesktopWidget

from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QCoreApplication, Qt

import requests
from socket import *
import os
from bs4 import BeautifulSoup
import urllib.request, urllib.error, urllib.parse
import re
from pprint import pprint
import ssl
import webbrowser

class MyApp(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('anjinma scanner 1.0ver by arrester')
        self.setWindowIcon(QIcon('arrester.jpg'))
        self.setGeometry(500, 300, 500, 500)
        #self.statusBar().showMessage('anjinma web + port + vulnerability diagnosis scanner by arrester')
#pixmap
        pixmap = QPixmap('anjinmascanner.jpg')

        lbl_img = QLabel()
        lbl_img.setPixmap(pixmap)

        vbox = QVBoxLayout()
        vbox.addWidget(lbl_img)

        self.move(300, 300)

#textbrowser
        self.le = QLineEdit()
        self.le.setPlaceholderText('Please enter an address to scan')
        vbox.addWidget(self.le, 0)
        self.le.returnPressed.connect(self.check) #enter key use
        self.btn = QPushButton('Input Check')
        self.btn.clicked.connect(self.check)
        vbox.addWidget(self.btn, 0)

        self.le2 = QLineEdit()
        self.le2.setPlaceholderText('Please enter a tag to crawl')
        vbox.addWidget(self.le2, 0)
        self.le2.returnPressed.connect(self.check) #enter key use
        self.btn2 = QPushButton('Crawl tag Input Check')
        self.btn2.clicked.connect(self.check)
        vbox.addWidget(self.btn2, 0)

        #self.lbl = QLabel('')

        self.tb = QTextBrowser()
        self.tb.setAcceptRichText(True)
        self.tb.setOpenExternalLinks(True)

        #vbox.addWidget(self.le, 0)
        #vbox.addWidget(self.btn, 0)
        #vbox.addWidget(self.lbl, 1)
        vbox.addWidget(self.tb, 300)

        self.btn3 = QPushButton('Contents Reset')
        self.btn3.clicked.connect(self.reset)
        vbox.addWidget(self.btn3, 0)


#button
        webscanButton = QPushButton('Web Scan')
        webscanButton.clicked.connect(self.webscan)
        portscanButton = QPushButton('Port Scan')
        portscanButton.clicked.connect(self.portscan)
        dirscanButton = QPushButton('Directory Scan')
        dirscanButton.clicked.connect(self.dirscan)
        vulnerscanButton = QPushButton('Vulner Scan')
        vulnerscanButton.clicked.connect(self.vulnerscan)
        crawlingButton = QPushButton('Crawling')
        crawlingButton.clicked.connect(self.crawling)
        saveButton = QPushButton('Save')
        saveButton.clicked.connect(self.save)
        inquiryButton = QPushButton('Inquiry (문의)')
        inquiryButton.clicked.connect(self.inquiry)

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(webscanButton)
        hbox.addWidget(portscanButton)
        hbox.addWidget(dirscanButton)
        hbox.addWidget(vulnerscanButton)
        hbox.addWidget(crawlingButton)
        hbox.addWidget(saveButton)
        hbox.addWidget(inquiryButton)
        hbox.addStretch(1)

        vbox.addStretch(9)
        vbox.addLayout(hbox)
        vbox.addStretch(1)

        self.setLayout(vbox)
        self.center()
        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def check(self):
        QMessageBox.about(self, "Check", "Success")

#webscanner append only str ! -_-;
    def webscan(self):
        url = self.le.text()
        if url == "":
            QMessageBox.about(self, "Notice", "please input address")
        else:
            r = requests.get(url)
            data1 = r.url
            data2 = str(r.status_code)
            data3 = str(r.headers)
            data4 = str(r.cookies)
            self.tb.append("Web Scanning...")
            self.tb.append('[◈] URL → '+data1)
            self.tb.append('[◈] Connect → '+data2)
            self.tb.append('[◈] Header → '+data3)
            self.tb.append('[◈] Cookie → '+data4)
            self.tb.append("")
            self.le.clear()

#portscan_test ip + port scanning :)  Port scanning takes a little time. Usually 23 to 24 seconds
    def portscan(self):
        url = self.le.text()
        if url == "":
            QMessageBox.about(self, "Notice", "please input address")
        else:
            s = socket(AF_INET, SOCK_DGRAM)
            s.connect((url,80))
            ipscan = s.getsockname()[0]

            port = [80, 20, 21, 22, 23, 25, 53, 5357, 110, 123, 161, 443, 1433, 3306, 1521, 8080, 135, 139, 137, 138, 445, 514, 8443, 3389, 8090, 42, 70, 79, 88, 118, 156, 220]
            host = url

            self.tb.append("IP and Port Scanning...")
            self.tb.append('[◈] IP → '+ipscan)

            target_ip = gethostbyname(host)
            opened_ports = []
            for p in port:
                sock = socket(AF_INET, SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, p))

                if result == 0:
                    opened_ports.append(str(p))

            for i in opened_ports:
                self.tb.append('[◈] Open Port : '+ i)

            self.tb.append("")
            self.le.clear()
            #print("")

#directory scan (dirscan)
    def dirscan(self):
        url = self.le.text()
        if url == "":
            QMessageBox.about(self, "Notice", "please input address")
        else:
            self.tb.append("Directory Scanning...")

            f = open("./dir_scan_list.txt", 'r')
            while True:
                data = f.readline()
                r = requests.get(url+data)
                if r.status_code == 200:
                    self.tb.append("[◈] Connect → " + r.url)
                if not data: break

            self.tb.append("")
            self.le.clear()
            f.close()

#webvulnerscan // reference: https://github.com/Dk20/WebVulnerabilityScanner
    def vulnerscan(self):
        url = self.le.text()
        if url == "":
            QMessageBox.about(self, "Notice", "please input address")
        else:
            self.tb.append("Vulner Scanning...")
            try:
                    page=urllib.request.urlopen(url)
                    parts = url.split("/")
                    self.tb.append(parts[-1])
                    if (parts[-1]=="admin"):
                            self.tb.append("         "+"         "+"Admin label vulnerability!!!!")
                    elif (parts[-1]=="login"):
                            self.tb.append("         "+"         "+"Login label vulnerability!!")
                    else :
                            soup = BeautifulSoup(page,"html.parser")
                            for form in soup.findAll('form'):
                                    self.tb.append("         "+"         Form Method:",form.get('method'))
                                    if(form.get('method')=='GET' or form.get('method')=='get'):
                                            self.tb.append("         "+"         "+"request sent via get method... data Vulnerable!!!")
                            try:
                                    result=requests.get(url+"'")
                                    self.tb.append("         "+"         "+"On preliminary sql injection status code :",str(result.status_code))
                                    self.tb.append("         "+"         ")
                                    self.tb.append("         "+"         ")
                                    self.tb.append("         "+"         "+"On preliminary sql injection response header from server :")
                                    self.tb.append("         "+"         ")
                                    #print("         "+"         ",result.headers)
                                    pprint(result.headers,width=1,indent=3)
                                    self.tb.append("         "+"         ")
                                    self.tb.append("         "+"         ")
                                    self.tb.append("         "+"         ")
                                    self.tb.append("         "+"         ")
                                    a=[404,500,408,302]
                                    if(result.status_code in a):
                                            self.tb.append("         "+"         "+"Wow! I think this site is vulnerable. Partial or 100% injection attacks are possible")
                            except:
                                    self.tb.append("         "+"         "+"Request denied, This page is safe...... :-)")
            except:
                    self.tb.append("         "+"         "+"This site does not have an ssl certificate... Vulnerable!!!")
                    self.tb.append("         "+"         "+"Exiting..........")

            self.tb.append("")
            self.le.clear()

#crawling
    def crawling(self):
        url = self.le.text()
        if url == "":
            QMessageBox.about(self, "Notice", "please input address")
        else:
            web_data = requests.get(url)
            soup = BeautifulSoup(web_data.text, "html.parser")
            crawling = self.le2.text()
            for list1 in soup.select(crawling):
                # enter: #latest > ul
                self.tb.append("Crawling...")
                self.tb.append(list1.get_text())

            self.le.clear()
            self.le2.clear()

#save file create
    def save(self):
        QMessageBox.about(self, "Notice", "Save file create success → data.txt") 
        data = self.tb.toPlainText()
        f = open("data.txt", 'w')
        f.write(data)
        f.close()

#inquiry
    def inquiry(self):
        QMessageBox.about(self, "inquiry 문의 made by arrester", '''https://blog.naver.com/lstarrlodyl → arrester blog
https://github.com/arrester → arrester github
arresterloyal@gmail.com → arrester email''')
        blog = "https://blog.naver.com/lstarrlodyl"
        webbrowser.open(blog)

#contents reset
    def reset(self):
        close = QMessageBox.question(self, 'Notice', 'Is it okay to initialize the content?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if close == QMessageBox.Yes:
            self.tb.clear()
        else:
            exit

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())

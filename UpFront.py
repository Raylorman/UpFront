#!/usr/bin/env python
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication, QLabel, QTextBrowser,\
    QLineEdit, QTableWidget, QTableWidgetItem, QProgressBar, QListWidgetItem, QListWidget, QTreeView,\
    QFileSystemModel, QMenu
from PyQt5.QtCore import QThread, pyqtSignal, QDateTime, QFile, QSettings, QVariant, QPoint, QSize, Qt, QDir, QEvent
from PyQt5.QtGui import QIcon, QBrush, QColor, QFont, QKeySequence
from PyQt5 import uic
import qdarktheme
import hashlib
import sys
import os
import datetime
from subprocess import check_output
import time
from binascii import b2a_hex, hexlify
import sqlite3
import re
import json
import pefile
from ppdeep import hash_from_file, hash, compare
import ppdeep
import lief
from lief import PE
from lief.PE import oid_to_string
import virustotal_python
from win32api import GetFileVersionInfo, HIWORD, LOWORD
import get_pe_data
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import pyminizip as pyzip
import shutil
import ctypes
try:
    from Registry import Registry
except ImportError:
    print("[!] python-registry not found")


c = ","
sig = "4d5a"
D = "::"
time_now = str(datetime.datetime.now().strftime("%d-%m-%Y %H%M%S"))


class PeCompare(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')    # Send update to Text Browser
    signal2 = pyqtSignal('PyQt_PyObject')    # Send Label Updates
    signal3 = pyqtSignal('PyQt_PyObject','PyQt_PyObject')    # Send progress bar

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        # def compare(source_binary, target_binary, source_file, target_file):
        self.signal3.emit(0, "Starting")

        source_file = self.pe_compare_data[0]
        target_file = self.pe_compare_data[1]
        source_binary = PE.parse(source_file)
        target_binary = PE.parse(target_file)
        source_file_name, target_file_name = os.path.basename(source_file), os.path.basename(target_file)
        source_file_name1, source_extension = os.path.splitext(source_file_name)
        target_file_name1, target_extension = os.path.splitext(target_file_name)
        source_file_size, target_file_size = os.path.getsize(source_file), os.path.getsize(target_file)
        source_sections, target_sections = source_binary.sections, target_binary.sections
        source_dict, target_dict = {}, {}
        self.signal3.emit(5, "Gathering Hashes")
        source_dict.update({'F_Name': source_file_name1, 'F_Ext': source_extension, 'F_Size': source_file_size})
        target_dict.update({'F_Name': target_file_name1, 'F_Ext': target_extension, 'F_Size': target_file_size})
        source_fuzzy = hash_from_file(source_file)
        target_fuzzy = hash_from_file(target_file)
        self.signal3.emit(15, "Checking Source")
        if source_fuzzy != target_fuzzy:
            source_dict['SSDeep'], target_dict['SSDeep'] = (source_fuzzy), (target_fuzzy)
            with open(source_file, 'rb') as source_in, open(target_file, 'rb') as target_in:
                s_binary_header, t_binary_header = source_in.read(32), target_in.read(32)
                s_header, t_header = b2a_hex(s_binary_header).decode(), b2a_hex(t_binary_header).decode()
                source_dict['First_Hex'] = (s_header)
                target_dict['First_Hex'] = (t_header)
                source_in.seek(0, 0), target_in.seek(0, 0)
                for s_section in source_sections:
                    s_flags = ""
                    for flag in s_section.characteristics_lists:
                        s_flags += str(flag).split(".")[-1] + " "
                    source_dict[s_section.name + ' Offset'] = s_section.offset
                    source_dict[s_section.name + ' Size'] = s_section.size
                    source_dict[s_section.name + ' Percent of File'] = round(s_section.size / source_file_size * 100, 2)
                    source_dict[s_section.name + ' Virtual Address'] = s_section.virtual_address
                    source_dict[s_section.name + ' Virtual Size'] = s_section.virtual_size
                    source_dict[s_section.name + ' Flags'] = s_flags
                    source_dict[s_section.name + ' Entropy'] = round(s_section.entropy, 4)
                    source_in.seek(s_section.offset)  # Raw Address Offset
                    s_sha256 = hashlib.sha256()
                    s_data = source_in.read(s_section.size)  # Raw Size
                    s_sha256.update(s_data)
                    source_dict[s_section.name + ' SHA256'] = s_sha256.hexdigest()
                    source_in.seek(s_section.offset)
                    s_head = source_in.read(32)
                    source_head = b2a_hex(s_head).decode()
                    source_dict[s_section.name + ' First Hex'] = source_head
                    source_dict[s_section.name + ' SSDeep'] = ppdeep.hash(s_data)
                    self.signal3.emit(25, "Source Checked")
                for t_section in target_sections:
                    t_flags = ""
                    for flag in t_section.characteristics_lists:
                        t_flags += str(flag).split(".")[-1] + " "
                    self.signal3.emit(45, "Checking Target")
                    target_dict[t_section.name + ' Offset'] = t_section.offset
                    target_dict[t_section.name + ' Size'] = t_section.size
                    target_dict[t_section.name + ' Percent of File'] = round(t_section.size / target_file_size * 100, 2)
                    target_dict[t_section.name + ' Virtual Address'] = t_section.virtual_address
                    target_dict[t_section.name + ' Virtual Size'] = t_section.virtual_size
                    target_dict[t_section.name + ' Flags'] = t_flags
                    target_dict[t_section.name + ' Entropy'] = round(t_section.entropy, 4)
                    target_in.seek(t_section.offset)  # Raw Address Offset
                    t_sha256 = hashlib.sha256()
                    t_data = source_in.read(t_section.size)  # Raw Size
                    t_sha256.update(t_data)
                    target_dict[t_section.name + ' SHA256'] = t_sha256.hexdigest()
                    target_in.seek(t_section.offset)
                    t_head = target_in.read(32)
                    target_head = b2a_hex(t_head).decode()
                    target_dict[t_section.name + ' First Hex'] = target_head
                    target_dict[t_section.name + ' SSDeep'] = ppdeep.hash(t_data)
                same_count = 0
                very_similiar_count = 0
                similiar_count = 0
                self.signal3.emit(60, "Comparing")
                for k, v in source_dict.items():
                    for k2, v2 in target_dict.items():
                        source_info = (str(k) + " (" + str(v) + ")")
                        target_info = (str(k2) + " (" + str(v2) + ")")
                        output_both = source_info + "\n" + target_info
                        if k == k2:
                            if v == v2:
                                self.signal1.emit('--SAME')
                                self.signal1.emit(output_both)
                                same_count += 1
                            else:
                                if 'SSDeep' in k and 'SSDeep' in k2:
                                    result = ppdeep.compare(v, v2)
                                    self.signal1.emit('--DIFF')
                                    self.signal1.emit(output_both)
                                    self.signal1.emit("SSDeep Comparison: " + str(result) + "%")
                                elif type(v) == int and type(v2) == int:
                                    if v > v2:
                                        percentage = round((v - v2) * 100 / v, 3)
                                        if percentage <= 0.5:
                                            self.signal1.emit('--INTEGER PAIR - ' + str(
                                                percentage) + "% Difference - VERY SIMILIAR (<=0.5)")
                                            self.signal1.emit(output_both)
                                            similiar_count += 1
                                        else:
                                            self.signal1.emit('--INTEGER PAIR - ' + str(percentage) + "% Difference")
                                            self.signal1.emit(output_both)
                                    else:
                                        percentage = round((v2 - v) * 100 / v2, 3)
                                        if percentage <= 0.5:
                                            self.signal1.emit('--INTEGER PAIR - ' + str(
                                                percentage) + "% Difference - VERY SIMILIAR (<=0.5)")
                                            self.signal1.emit(output_both)
                                            similiar_count += 1
                                        else:
                                            self.signal1.emit('--INTEGER PAIR - ' + str(percentage) + "% Difference")
                                            self.signal1.emit(output_both)
                                elif type(v) == float and type(v2) == float:
                                    if v > v2:
                                        percentage = round((v - v2) * 100 / v, 5)
                                        if percentage <= 0.1:
                                            self.signal1.emit('--FLOAT PAIR - ' + str(
                                                percentage) + "% Difference - VERY SIMILIAR (<=.1)")
                                            self.signal1.emit(output_both)
                                            similiar_count += 1
                                        else:
                                            self.signal1.emit('--FLOAT PAIR - ' + str(percentage) + "% Difference")
                                            self.signal1.emit(output_both)
                                    else:
                                        percentage = round((v2 - v) * 100 / v2, 5)
                                        if percentage <= 0.1:
                                            self.signal1.emit('--FLOAT PAIR - ' + str(
                                                percentage) + "% Difference - VERY SIMILIAR (<=.1)")
                                            self.signal1.emit(output_both)
                                            similiar_count += 1
                                        else:
                                            self.signal1.emit('--FLOAT PAIR - ' + str(percentage) + "% Difference")
                                            self.signal1.emit(output_both)
                                else:
                                    self.signal1.emit('--DIFF')
                                    self.signal1.emit(output_both)
            self.signal3.emit(80, "Finishing Up")
            scoring_metric = (same_count * 3) + (similiar_count * 2)
            print(str(scoring_metric))
            self.signal1.emit('Total comparisons from Source : ' + str(len(source_dict)))
            self.signal1.emit('Total comparisons from Target : ' + str(len(target_dict)))
            self.signal1.emit('Sections that were Identical  : ' + str(same_count))
            self.signal1.emit('Sections that were Similar    : ' + str(similiar_count))
            self.signal1.emit("")
            scoring_metric_out = ''
            if scoring_metric <= 40:
                scoring_metric_out = 'Different (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric <= 60 and scoring_metric > 40:
                scoring_metric_out = 'Minor Similiarities (' + str(scoring_metric) + ")"
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric <= 90 and scoring_metric > 60:
                scoring_metric_out ='Moderate Similiaties (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric <= 130 and scoring_metric > 90:
                scoring_metric_out = 'Significant Similiaties (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric <= 145 and scoring_metric > 130:
                scoring_metric_out = 'Very High Similarities (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric <= 160 and scoring_metric > 145:
                scoring_metric_out = 'Extremely High Similarities (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            elif scoring_metric > 160:
                scoring_metric_out = 'Almost Same File (' + str(scoring_metric) + ')'
                self.signal1.emit(scoring_metric_out)
            sig2 = str(len(source_dict)), str(len(target_dict)), str(same_count), str(similiar_count), scoring_metric_out
            self.signal2.emit(sig2)
            print(sig2)
        else:
            self.signal1.emit(source_file_name + " - " + str(source_fuzzy))
            self.signal1.emit(target_file_name + " - " + str(target_fuzzy))
            self.signal1.emit('Scoring Metric: Same File Using SSDeep')
        self.signal3.emit(100, "Comparison Complete")










        #
        #
        # source_binary = PE.parse(source_file)
        # target_binary = PE.parse(target_file)
        # source_file_name = os.path.basename(source_file)
        # target_file_name = os.path.basename(target_file)
        # source_file_name1, source_extension = os.path.splitext(source_file_name)
        # target_file_name1, target_extension = os.path.splitext(target_file_name)
        # source_file_size, target_file_size = os.path.getsize(source_file), os.path.getsize(target_file)
        # source_sections, target_sections = source_binary.sections, target_binary.sections
        # source_dict = {}
        # target_dict = {}
        # source_dict['File_Name'] = (source_file_name1)
        # target_dict['File_Name'] = (target_file_name1)
        # source_dict['Extension'] = (source_extension)
        # target_dict['Extension'] = (target_extension)
        # source_dict['File_Size'] = (source_file_size)
        # target_dict['File_Size'] = (target_file_size)
        # source_fuzzy = hash_from_file(source_file)
        # target_fuzzy = hash_from_file(target_file)
        # source_dict['SSDeep'] = (source_fuzzy)
        # target_dict['SSDeep'] = (target_fuzzy)
        # with open(source_file, 'rb') as source_in, open(target_file, 'rb') as target_in:
        #     s_binary_header = source_in.read(32)
        #     s_header = b2a_hex(s_binary_header).decode()
        #     t_binary_header = target_in.read(32)
        #     t_header = b2a_hex(t_binary_header).decode()
        #     source_dict['First_Hex'] = (s_header)
        #     target_dict['First_Hex'] = (t_header)
        #     source_in.seek(0, 0)
        #     target_in.seek(0, 0)
        #     for s_section in source_sections:
        #         s_flags = ""
        #         for flag in s_section.characteristics_lists:
        #             s_flags += str(flag).split(".")[-1] + " "
        #         source_dict[s_section.name + ' Offset'] = s_section.offset
        #         source_dict[s_section.name + ' Size'] = s_section.size
        #         source_dict[s_section.name + ' Percent of File'] = round(s_section.size / source_file_size * 100, 2)
        #         source_dict[s_section.name + ' Virtual Address'] = s_section.virtual_address
        #         source_dict[s_section.name + ' Virtual Size'] = s_section.virtual_size
        #         source_dict[s_section.name + ' Flags'] = s_flags
        #         source_dict[s_section.name + ' Entropy'] = round(s_section.entropy, 4)
        #         source_in.seek(s_section.offset)               # Raw Address Offset
        #         s_sha256 = hashlib.sha256()
        #         s_data = source_in.read(s_section.size)        # Raw Size
        #         s_sha256.update(s_data)
        #         source_dict[s_section.name + ' SHA256'] = s_sha256.hexdigest()
        #         source_dict[s_section.name + ' SSDeep'] = hash(s_data)
        #     for t_section in target_sections:
        #         t_flags = ""
        #         for flag in t_section.characteristics_lists:
        #             t_flags += str(flag).split(".")[-1] + " "
        #         target_dict[t_section.name + ' Offset'] = t_section.offset
        #         target_dict[t_section.name + ' Size'] = t_section.size
        #         target_dict[t_section.name + ' Percent of File'] = round(t_section.size / target_file_size * 100, 2)
        #         target_dict[t_section.name + ' Virtual Address'] = t_section.virtual_address
        #         target_dict[t_section.name + ' Virtual Size'] = t_section.virtual_size
        #         target_dict[t_section.name + ' Flags'] = t_flags
        #         target_dict[t_section.name + ' Entropy'] = round(t_section.entropy, 4)
        #         target_in.seek(t_section.offset)               # Raw Address Offset
        #         t_sha256 = hashlib.sha256()
        #         t_data = source_in.read(t_section.size)        # Raw Size
        #         t_sha256.update(t_data)
        #         target_dict[t_section.name + ' SHA256'] = t_sha256.hexdigest()
        #         target_dict[t_section.name + ' SSDeep'] = hash(t_data)
        #     same_count = 0
        #     similiar_count = 0
        #     for k, v in source_dict.items():
        #         for k2, v2 in target_dict.items():
        #             if k == k2:
        #                 if v == v2:
        #                     print('--SAME')
        #                     print(str(k) + " (" + str(v) + ")")
        #                     print(str(k2) + " (" + str(v2) + ")")
        #                     same_count +=1
        #                 else:
        #                     if 'SSDeep' in k and 'SSDeep' in k2:
        #                         result = ppdeep.compare(v, v2)
        #                         print('--DIFF')
        #                         print(str(k + " (" + str(v) + ")"))
        #                         print(str(k2 + " (" + str(v2) + ")"))
        #                         print("SSDeep Comparison: " + str(result) + "%")
        #                     elif type(v) == int and type(v2) == int:
        #                         if v > v2:
        #                             percentage = round((v - v2) * 100 / v, 3)
        #                             if percentage <= 0.5:
        #                                 print('--INTEGER PAIR - ' + str(percentage) + "% Difference - VERY SIMILIAR (<=0.5)")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                                 similiar_count += 1
        #                             else:
        #                                 print('--INTEGER PAIR - ' + str(percentage) + "% Difference")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                         else:
        #                             percentage = round((v2 - v) * 100 / v2, 3)
        #                             if percentage <= 0.5:
        #                                 print('--INTEGER PAIR - ' + str(percentage) + "% Difference - VERY SIMILIAR (<=0.5)")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                                 similiar_count += 1
        #                             else:
        #                                 print('--INTEGER PAIR - ' + str(percentage) + "% Difference")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                     elif type(v) == float and type(v2) == float:
        #                         if v > v2:
        #                             percentage = round((v - v2) * 100 / v, 5)
        #                             if percentage <= 0.1:
        #                                 print('--FLOAT PAIR - ' + str(percentage) + "% Difference - VERY SIMILIAR (<=.1)")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 similiar_count += 1
        #                             else:
        #                                 print('--FLOAT PAIR - ' + str(percentage) + "% Difference")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                         else:
        #                             percentage = round((v2 - v) * 100 / v2, 5)
        #                             if percentage <= 0.1:
        #                                 print('--FLOAT PAIR - ' + str(percentage) + "% Difference - VERY SIMILIAR (<=.1)")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                                 similiar_count += 1
        #                             else:
        #                                 print('--FLOAT PAIR - ' + str(percentage) + "% Difference")
        #                                 print(str(k + " (" + str(v) + ")"))
        #                                 print(str(k2 + " (" + str(v2) + ")"))
        #                     else:
        #                         print('--DIFF')
        #                         print(str(k + " (" + str(v) + ")"))
        #                         print(str(k2 + " (" + str(v2) + ")"))
        #
        #     print('Total comparisons from Source : ' + str(len(source_dict)))
        #     print('Total comparisons from Target : ' + str(len(target_dict)))
        #     print('Sections that were Identical  : ' + str(same_count))
        #     print('Sections that were Similar    : ' + str(similiar_count))


class CreateReports(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        # items = self.report_items
        # print(self.report_items)
        file_name = self.report_items[0]
        file_ext = self.report_items[1]
        file_size = self.report_items[2]
        created = self.report_items[3]
        modified = self.report_items[4]
        accessed = self.report_items[5]
        version = self.report_items[6]
        file_path = self.report_items[7]
        md5 = self.report_items[8]
        sha1 = self.report_items[9]
        out_loc = self.report_items[10]
        binary = PE.parse(file_path)
        dos_header = binary.dos_header
        header = binary.header
        optional_header = binary.optional_header


        # with open(file_path, 'rb') as in_file2:
        #     header_string = ""
        #     bytes = 0
        #     line = []
        #     filecontents = in_file2.read()
        #     for b in filecontents:
        #         bytes = bytes + 1
        #         line.append(b)
        #         if bytes == 17:
        #             pass
        #         else:
        #             for b2 in line:
        #                 if (b2 >= 32) and (b2 <= 126):
        #                     header_string += (chr(b2))
        #                 else:
        #                     header_string += ("*")
        #     print(header_string)
        fileName = out_loc + "/Upfront_Reports/UpfrontReport - " + file_name + ".pdf"
        if os.path.exists(fileName):
            print("File is already there - " + fileName)
            return
        else:
            with open(file_path, 'rb') as in_file:
                binary_header = in_file.read(16)
                file_header = b2a_hex(binary_header).decode()
            documentTitle = 'UpFront Report ' + file_name + " - " + sha1
            title = 'UpFront File Report'
            subTitle = file_name + " >> SHA1: " + sha1
            pdf = canvas.Canvas(fileName)
            pdf.setTitle(documentTitle)
            pdf.setFillColor(colors.navy)
            pdf.setFont("Courier-Bold", 12)
            pdf.drawCentredString(300, 770, title)
            pdf.setFillColor(colors.maroon)
            pdf.setFont("Courier", 10)
            pdf.drawCentredString(290, 720, subTitle)
            pdf.line(30, 710, 550, 710)
            text = pdf.beginText(40, 680)
            text.setFont("Courier", 9)
            text.setFillColor(colors.black)
            text.textLine("Name       :  " + file_name)
            text.textLine("Ext        :  " + file_ext)
            text.textLine("Size       :  " + file_size)
            text.textLine("Path       :  ")
            text.textLine("    "  + file_path)
            text.textLine("Version    :  " + version)
            text.textLine("Created    :  " + created)
            text.textLine("Modified   :  " + modified)
            text.textLine("Accessed   :  " + accessed)
            text.textLine("MD5        :  " + md5)
            text.textLine("SHA1       :  " + sha1)
            fuzzy_hash = hash_from_file(file_path)
            text.textLine("SSDeep     :  " + fuzzy_hash)
            imp_hash = PE.get_imphash(binary)
            text.textLine("ImpHash    :  " + imp_hash)
            text.textLine("Machine    :  " + str(header.machine))
            text.textLine("Start Hex  :  " + ' '.join([file_header[i:i+2] for i in range(0, len(file_header), 2)]))
            data_directories = binary.data_directories
            text.textLine("")
            text.textLine("== Data Directories ==")
            f_title = "|{:<24} | {:<10} | {:<10} | {:<8} |"
            f_value = "|{:<24} | 0x{:<8x} | 0x{:<8x} | {:<8} |"
            text.textLine(f_title.format("Type", "RVA", "Size", "Section"))
            for directory in data_directories:
                section_name = directory.section.name if directory.has_section else ""
                text.textLine(f_value.format(str(directory.type).split('.')[-1], directory.rva, directory.size, section_name))
            pdf.drawText(text)
            pdf.save()
            inpt = file_path
            pre = None
            oupt = out_loc + "/Upfront_Reports/Export- " + file_name + " - " + sha1 + ".zip"
            password = "infected"
            com_lvl = 5
            pyzip.compress(inpt, pre, oupt, password, com_lvl)


class GetCerts(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')  # Send VALID Cert Data
    signal2 = pyqtSignal('PyQt_PyObject')  # Send CERT Progress

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        report_loc = self.certs_data
        db_path = report_loc + "\\Data\\file_checks (" + time_now + ").db"
        try:
            sqliteConnection = sqlite3.connect(db_path)
            cursor = sqliteConnection.cursor()
        except sqlite3.Error as error:
            return
            # print("LOG:{0:8}".format("Failed to connect with sqlite3 database - " + str(error)))
        try:
            cursor.execute("SELECT * FROM files_to_check")  # execute a simple SQL select query
        except sqlite3.OperationalError as sqe:
            print(str(sqe))
            return
        total_items = len(cursor.fetchall())
        progress = 100 / total_items
        counter = 0
        cursor.execute("SELECT * FROM files_to_check")
        jobs = cursor.fetchall()  # get all the results from the above query
        for file in jobs:
            file_name = str(file[0])
            file_path = str(file[7])
            file_sha1 = str(file[9])
            counter += 1
            try:
                pe = lief.parse(file_path)
                signature1 = pe.signatures[0]
                signature2 = pe.verify_signature()
                if signature2 == lief.PE.Signature.VERIFICATION_FLAGS.OK:
                    status = "VALID"
                    auth_hash = signature1.content_info.digest.hex()
                    signer = signature1.signers[0]
                    output = str(file_name), str(status), str(signer), str(auth_hash), str(file_path), str(file_sha1)
                    self.signal1.emit(output)
                else:
                    status = str(signature2).replace("VERIFICATION_FLAGS.", "")
                    auth_hash = signature1.content_info.digest.hex()
                    signer = signature1.signers[0]
                    output = str(file_name), str(status), str(signer), str(auth_hash), str(file_path), str(file_sha1)
                    self.signal1.emit(output)
            except Exception as ee:
                output = str(file_name), "OTHER/NONE", "", "", str(file_path), str(file_sha1)
                self.signal1.emit(output)
                print(str(ee))
                pass

            self.signal2.emit(progress * counter)
        self.signal2.emit(100)
        cursor.close()


class PeData(QThread):
    signal = pyqtSignal('PyQt_PyObject')   # Clear GUI Signal
    signal1 = pyqtSignal('PyQt_PyObject')  # Basic Info
    signal2 = pyqtSignal('PyQt_PyObject')  # Data Directories
    signal3 = pyqtSignal('PyQt_PyObject')  # Header
    signal4 = pyqtSignal('PyQt_PyObject')  # Imports
    signal5 = pyqtSignal('PyQt_PyObject')  # Relocations
    signal6 = pyqtSignal('PyQt_PyObject')  # Sections
    signal7 = pyqtSignal('PyQt_PyObject')  # Symbols
    signal8 = pyqtSignal('PyQt_PyObject')  # TLS
    signal9 = pyqtSignal('PyQt_PyObject')  # Export
    signal10 = pyqtSignal('PyQt_PyObject')  # Debug
    signal11 = pyqtSignal('PyQt_PyObject')  # Signature
    signal12 = pyqtSignal('PyQt_PyObject')  # Rich Header
    signal13 = pyqtSignal('PyQt_PyObject')  # Resources
    signal14 = pyqtSignal('PyQt_PyObject')  # Load Configurations
    signal15 = pyqtSignal('PyQt_PyObject')  # Constructors
    signal16 = pyqtSignal('PyQt_PyObject')  # Functions
    signal17 = pyqtSignal('PyQt_PyObject')  # Exceptions
    signal18 = pyqtSignal('PyQt_PyObject')  # Delay Imports
    signal19 = pyqtSignal('PyQt_PyObject','PyQt_PyObject')  # Progress Bar

    def __init__(self):
        QThread.__init__(self)


    def run(self):
        self.signal.emit("GO")
        self.signal19.emit(0, "Starting")
        file_path = self.pe_data[0]
        get_fuzzy = self.pe_data[2]
        binary = PE.parse(file_path)

        self.signal19.emit(1, "Basic Info")
        for item in get_pe_data.get_information(binary, file_path, get_fuzzy):
            self.signal1.emit(str(item))

        self.signal19.emit(2, "Data Directories")
        for item in get_pe_data.get_data_directories(binary):
            self.signal2.emit(str(item))

        self.signal19.emit(3, "Headers")
        for item in get_pe_data.get_header(binary):
            self.signal3.emit(str(item))

        self.signal19.emit(4, "Imports")
        for item in get_pe_data.get_imports(binary):
            self.signal4.emit(str(item))

        self.signal19.emit(5, "Relocations")
        for item in get_pe_data.get_relocations(binary):
            self.signal5.emit(str(item))

        self.signal19.emit(6, "Sections")
        for item in get_pe_data.get_sections(binary):
            self.signal6.emit(str(item))

        self.signal19.emit(7, "Symbols")
        for item in get_pe_data.get_symbols(binary):
            self.signal7.emit(str(item))

        self.signal19.emit(8, "TLS")
        for item in get_pe_data.get_tls(binary):
            self.signal8.emit(str(item))

        self.signal19.emit(9, "GExports")
        for item in get_pe_data.get_export(binary):
            self.signal9.emit(str(item))

        self.signal19.emit(10, "Debug Info")
        for item in get_pe_data.get_debug(binary):
            self.signal10.emit(str(item))

        self.signal19.emit(11, "Signatures")
        for item in get_pe_data.get_signature(binary, file_path):
            self.signal11.emit(str(item))

        self.signal19.emit(12, "Rich Header")
        for item in get_pe_data.get_rich_header(binary, file_path):
            self.signal12.emit(str(item))

        self.signal19.emit(13, "Resources")
        for item in get_pe_data.get_resources(binary):
            self.signal13.emit(str(item))

        self.signal19.emit(14, "Load Configuration")
        try:
            for item in get_pe_data.get_load_configuration(binary):
                self.signal14.emit(str(item))
        except TypeError as ve:
            self.signal14.emit(str("None"))

        self.signal19.emit(15, "Constructors")
        for item in get_pe_data.get_ctor(binary):
            self.signal15.emit(str(item))

        self.signal19.emit(16, "Functions")
        for item in get_pe_data.get_functions(binary):
            self.signal16.emit(str(item))

        self.signal19.emit(17, "Exceptions")
        for item in get_pe_data.get_exception_functions(binary):
            self.signal17.emit(str(item))

        self.signal19.emit(18, "Delay Imports")
        for item in get_pe_data.get_delay_imports(binary):
            self.signal18.emit(str(item))

        self.signal19.emit(18, "Break-Out Complete")


class VtLookup(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')  # Update left window pane with main results
    # signal2 = pyqtSignal('PyQt_PyObject')  # Not used
    signal3 = pyqtSignal('PyQt_PyObject')  # Update right pane with items if it is malicious

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        file_hash = self.vt_hash[0]
        vt_api_key = self.vt_hash[1]
        # print("VirusTotal Thread Activated")
        self.signal1.emit("Gathering info by hash: " + file_hash)
        # try:
        with virustotal_python.Virustotal(vt_api_key) as vtotal:
            try:
                response = vtotal.request(f"files/{file_hash}")
                if response.status_code == 200:
                    result = response.json()
                    if result.get("data").get("attributes").get("last_analysis_results"):
                        stats = result.get("data").get("attributes").get("last_analysis_stats")
                        results = result.get("data").get("attributes").get("last_analysis_results")
                        self.signal1.emit("Malicious  : " + str(stats.get("malicious")))
                        self.signal1.emit("Undetected : " + str(stats.get("undetected")))
                        for k in results:
                            if results[k].get("category") == "malicious":
                                self.signal3.emit(results[k].get("engine_name"))
                                self.signal3.emit("version  : " + results[k].get("engine_version"))
                                self.signal3.emit("category : " + results[k].get("category"))
                                self.signal3.emit("result   : " + results[k].get("result"))
                                self.signal3.emit("method   : " + results[k].get("method"))
                                self.signal3.emit("update   : " + results[k].get("engine_update"))
                                self.signal3.emit(("*" * 25), "\n")
                            else:
                                self.signal3.emit("Undetected - " + results[k].get("engine_name"))
                        self.signal1.emit("Lookup Completed: OK")
                    else:
                        self.signal1.emit("Failed to analyze...")
                elif response.status_code == 404:
                    self.signal1.emit("No Information available for this file...")
                    self.signal1.emit("Response from Server, Status code: " + str(response.status_code))
                elif response.status_code == 400:
                    self.signal1.emit("ERROR CODE 400 - Bad Request")
                else:
                    self.signal1.emit("Something went wrong wqith Request. Code is not 400, 404, or 200")
            except virustotal_python.virustotal.VirustotalError as vt_e:
                self.signal1.emit("No matches found this file on Server: " + (file_hash))
                self.signal1.emit("Response from Server (Status code): " + str(vt_e))
            except:
                self.signal1.emit("Your missing something here, review your API key Info")
                self.signal1.emit("Any Unhandled Exception Occured")
        # except:
        #     self.signal1.emit("Invalid API Key or lookups are exhausted for this Key - API: " + vt_api_key)
        #     self.signal1.emit("https://developers.virustotal.com/reference/overview")
        # return


class RunStrings(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')
    signal2 = pyqtSignal('PyQt_PyObject')  # Progress bar updated
    signal3 = pyqtSignal('PyQt_PyObject')  # Key Strings sent
    signal4 = pyqtSignal('PyQt_PyObject')  # send base64

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        target_file = self.file_strings[0]
        string_size = int(self.file_strings[1])
        custom_re = self.file_strings[2]
        self.signal2.emit(0)
        word = ''
        file_size = os.path.getsize(target_file)
        progress = 100/file_size
        bytes = 0
        update = 0
        format_str = "{:<18}{:<2}"
        list = []
        if string_size < 3:
            string_size == 3
        with open(target_file, 'rb') as f:
            for b in f.read():
                bytes += 1
                if (b >= 32) and (b <= 126):
                    word = word + chr(b)
                else:
                    if word != "" and len(word) >= string_size:
                        list.append(word)
                    word = ''
                    update += 1
                if update % 3000 == 0:
                    self.signal2.emit(progress * bytes)

        for word in list:
            try:
                base64_bytes = word.encode("ascii")
                if self.isBase64(word) == True:
                    string_bytes = base64.b64decode(base64_bytes)
                    b64_out = (word, "Decoded: " + string_bytes.decode("ascii"))
                    self.signal4.emit(b64_out)
                else:
                    pass
            except TypeError as te:
                print(str(te))
                pass
        for item in list:
            self.signal1.emit(item)
            ip_match = re.search(
                r'(?<![-\.\d])(?:0{0,2}?[0-9]\.|1\d?\d?\.|2[0-5]?[0-5]?\.){3}(?:0{0,2}?[0-9]|1\d?\d?|2[0-5]?[0-5]?)(?![\.\d])',
                item)
            if ip_match:
                self.signal3.emit(format_str.format("IP:", item))
            else:
                pass
            url_match = re.search(
                r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))",
                item)
            if url_match:
                self.signal3.emit(format_str.format("URL:", item))
            else:
                pass
            if custom_re == "" or None:
                pass
            else:
                custom_match = re.search(r'{}'.format(custom_re),item)
                if custom_match:
                    self.signal3.emit(format_str.format("CUSTOM:", item))
                else:
                    pass
        self.signal2.emit(100)
        return

    def isBase64(self, sb):
        try:
            if isinstance(sb, str):
                sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                sb_bytes = sb
            else:
                raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
            return False


class HashThread(QThread):
    signal1 = pyqtSignal('PyQt_PyObject')  # Sends Scanned File Information to the full table list on GUI
    signal2 = pyqtSignal('PyQt_PyObject')  # Sends Current File checked Value to the Progress Bar
    signal3 = pyqtSignal('PyQt_PyObject')  # Updates lookups counts (Checked, SKipped, Errors) on Main GUI
    signal4 = pyqtSignal('PyQt_PyObject')  # Sends Final Hash_Completed Output to GUI
    signal5 = pyqtSignal('PyQt_PyObject')  # Keyword Found, sending data to Keyword hits table
    signal6 = pyqtSignal('PyQt_PyObject')  # Send the count of overall lookups to check
    signal7 = pyqtSignal('PyQt_PyObject')  # Send an Update for the Log
    signal8 = pyqtSignal('PyQt_PyObject')  # Send File Extensions
    signal9 = pyqtSignal('PyQt_PyObject', 'PyQt_PyObject', 'PyQt_PyObject')  # Send Registry Data

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        block_size = 65536
        error_count, other_count, header_match, skip_count, value_progress, starter_count = (0 for i in range(6))
        keyword_list, rat_list, files_to_check, registry_files = ([] for i in range(4))
        target_loc, report_loc, keyword_loc = self.dir_to_hash[0], self.dir_to_hash[1], self.dir_to_hash[2]
        rat_loc = "lookups\\RAT.txt"
        min_size, max_size = int(self.dir_to_hash[3]), int(self.dir_to_hash[4])
        format = "%d-%m-%Y %H:%M:%S.%f"
        keyword_list, rat_list, files_to_check, registry_files = ([] for i in range(4))
        version = ""
        start_date = datetime.datetime.strptime(self.dir_to_hash[5], format)
        end_date = datetime.datetime.strptime(self.dir_to_hash[6], format)
        temp_loc= "\\temp"
        # nsrl_loc = '\\nsrl'
        data_loc = "\\data"
        # logs_loc = "\\data\\logs"
        try:
            os.mkdir(report_loc + temp_loc)
        except FileExistsError:
            pass # self.signal7.emit("LOG\t:  Path Exists - " + (report_loc))
        # try:
        #     os.mkdir(report_loc + nsrl_loc)
        # except FileExistsError:
        #     pass # self.signal7.emit("LOG\t:  Path Exists - " + (report_loc))
        try:
            os.mkdir(report_loc + data_loc)
        except FileExistsError:
            pass # self.signal7.emit("LOG\t:  Path Exists - " + (report_loc))
        # try:
        #     os.mkdir(report_loc + logs_loc)
        # except FileExistsError:
        #     pass # self.signal7.emit("LOG\t:  Path Exists - " + (report_loc))

        report_path = report_loc + "\\Data\\" + "4d5a Report (" + time_now + ").csv"
        db_path = report_loc + "\\Data\\" + "file_checks (" + time_now + ").db"
        start_time = time.time()
        log = "LOG:"
        text_out = "Building Keyword List"
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        if keyword_loc == "":
            pass
        else:
            with open(keyword_loc, "r") as k_file:
                for line in k_file:
                    keywords = line.lower().rstrip()
                    keyword_list.append(keywords)
                k_file.close()
        with open(rat_loc, "r") as r_file:
            for line in r_file:
                rat = line.lower().rstrip()
                rat_list.append(rat)
            r_file.close()
        text_out = "Counting Files and creating temp files for Target Directory"
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        ext_counts = {}
        # try:
        if os.path.isfile(report_loc + "\\temp\\DONT_MODIFY.temp") == True:
            os.remove(report_loc + "\\temp\\DONT_MODIFY.temp")
        else:
            pass
        with open(report_loc + "\\temp\\DONT_MODIFY.temp", "a") as f:
            for root, dir, files in os.walk(target_loc, topdown=True):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_name1 = os.path.basename(file_path)
                    file_name, extension = os.path.splitext(file_name1)
                    if extension not in ext_counts:
                        ext_counts[str(extension)] = 1
                    else:
                        ext_counts[extension] += 1
                    try:
                        f.write(file_path + "\n")
                        starter_count += 1
                    except UnicodeEncodeError as ue:
                        pass
                        # print("Unicode ERROR with filepath: " + str(ue))
                        # print(file_path)
                    except AttributeError as ae:
                        pass
                        # print("Attribute ERROR with filepath: " + str(ae))
                        # print(file_path)

                    reg_files = []
                    if file_name1 == "SOFTWARE" or file_name1=="SYSTEM" or file_name1=="SAM"\
                            or file_name1=="SECURITY" or file_name1=="ntuser.dat":
                        text_out = "Registry File Found - " + file_path
                        self.signal7.emit("{0:<12}{1}".format(log, text_out))
                        with open(file_path, 'rb') as in_file:
                            binary_header = in_file.read(4)
                            file_header = b2a_hex(binary_header).decode()
                        if file_header == "72656766":
                            if os.path.exists(report_loc + "\\temp\\registry"):
                                pass
                            else:
                                os.mkdir(report_loc + "\\temp\\registry")
                            reg_file = report_loc + '\\temp\\registry\\' + file_name1
                            shutil.copy(file_path, report_loc + '\\temp\\registry\\' + file_name1)
                            reg_files.append(file_name1)
                    else:
                        pass
                    if "SYSTEM" in reg_files:
                        try:
                            # self.signal9.emit("---- Current Control Set - SYSTEM Registry")
                            target = report_loc + '\\temp\\registry\\SYSTEM'
                            key = self.pull_key(target, 'Select')
                            self.signal9.emit("Current ControlSet", str(key['Current']), 'SYSTEM>Select')
                            self.signal9.emit("Default ControlSet", str(key['Default']), 'SYSTEM>Select')
                            self.signal9.emit("Last Known Good ControlSet", str(key['LastKnownGood']), 'SYSTEM>Select')
                        except Exception as ee:
                            print("An Error Occured on SYSTEM File " + str(ee))

                        try:
                            # self.signal9.emit("---- Time Zone Info - SYSTEM Registry")
                            tz_loc = "ControlSet001\\Control\\TimeZoneInformation"
                            key = self.pull_key(target, tz_loc)
                            self.signal9.emit("Time Zone Setting", str(key['TimeZoneKeyName']), "SYSTEM>"+tz_loc)
                            self.signal9.emit("Active Time Bias", str("-" + str(int(key['ActiveTimeBias'] / 60))), "SYSTEM>"+tz_loc)
                            self.signal9.emit("Normal Bias", str("-" + str(int(key['Bias'] / 60))), "SYSTEM>"+tz_loc)
                        except Exception as ee:
                            print("An Error Occured on SYSTEM File " + str(ee))

                        try:
                            # self.signal9.emit("---- Firewall Settings - SYSTEM Registry")
                            fw_dom = "ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\DomainProfile"
                            fw_stan = "ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\StandardProfile"
                            key1 = self.pull_key(target, fw_dom)
                            key2 = self.pull_key(target, fw_stan)
                            self.signal9.emit('Domain FireWall', str(key1['EnableFirewall']) + '   1=Active (Default)', "SYSTEM>"+fw_dom)
                            self.signal9.emit('Standard FireWall', str(key2['EnableFirewall']) + '   1=Active (Default)', "SYSTEM>"+fw_stan)
                        except Exception as ee:
                            print("An Error Occured on SYSTEM File " + str(ee))

                        try:
                            # self.signal9.emit("---- System Architecture  - SYSTEM Registry")
                            registry = Registry.Registry(target)
                            sys_arch = "ControlSet001\\Control\\Session Manager\\Environment"
                            key = registry.open(sys_arch)
                            for v in key.values():
                                if v.name() == 'TEMP':
                                    self.signal9.emit("TEMP Path", v.value(), "SYSTEM>"+sys_arch)
                                if v.name() == 'TMP':
                                    self.signal9.emit("TMP Path", v.value(), "SYSTEM>"+sys_arch)
                                if v.name() == 'PROCESSOR_ARCHITECTURE':
                                    self.signal9.emit("Processor Architecture", v.value(), "SYSTEM>"+sys_arch)
                                if v.name() == 'NUMBER_OF_PROCESSORS':
                                    self.signal9.emit("Number of Processors",  str(v.value()), "SYSTEM>"+sys_arch)
                        except Exception as ee:
                            print("An Error Occured on SYSTTEM File " + str(ee))

                        #     # self.signal9.emit("\n---- Last Shutdown  - SYSTEM Registry)
                        #     # registry = Registry.Registry(target)
                        #     key = registry.open("ControlSet001\\Control\\Windows")
                        #     for v in key.values():
                        #         if v.name() == 'ShutdownTime':
                        #             a = (str(hexlify(v.value())))
                        #             b = (a.replace("'", ""))
                        #             c = (b[1:])
                        #             ba = bytearray.fromhex(c)
                        #             ba.reverse()
                        #             joins = ''.join(format(x, '02x') for x in ba)
                        #             super = str(joins.upper())
                        #             def getFiletime(dt):
                        #                 microseconds = int(dt, 16) / 10
                        #                 seconds, microseconds = divmod(microseconds, 1000000)
                        #                 days, seconds = divmod(seconds, 86400)
                        #                 return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, microseconds)
                        #             converted = (format(getFiletime(super), '%a, %d %B %Y - %H:%M:%S %Z'))
                        #             self.signal9.emit(format_str.format("Last Shutdown time: ", converted + " System Time"))

                    if "SOFTWARE" in reg_files:
                        try:
                            target = report_loc + '\\temp\\registry\\SOFTWARE'
                            registry1 = Registry.Registry(target)
                            prod_info = "Microsoft\\Windows NT\\CurrentVersion"
                            key = registry1.open(prod_info)
                            os_dic = {}
                            for v in key.values():
                                if v.name() == 'ProductName':
                                    os_dic['ProductName'] = v.value()
                                    self.signal9.emit("Product Name", os_dic['ProductName'], "SOFTWARE>"+prod_info)
                                if v.name() == 'EditionID':
                                    os_dic['EditionID'] = v.value()
                                    self.signal9.emit("Edition ID", os_dic['EditionID'], "SOFTWARE>"+prod_info)
                                if v.name() == 'ReleaseId':
                                    os_dic['ReleaseID'] = v.value()
                                    self.signal9.emit("Release ID", os_dic['ReleaseID'], "SOFTWARE>"+prod_info)
                                if v.name() == 'CurrentBuild':
                                    os_dic['CurrentBuild'] = v.value()
                                    self.signal9.emit("Current Build", os_dic['CurrentBuild'], "SOFTWARE>"+prod_info)
                                if v.name() == 'CurrentVersion':
                                    os_dic['CurrentVersion'] = v.value()
                                    self.signal9.emit("CurrentVersion", os_dic['CurrentVersion'], "SOFTWARE>"+prod_info)
                                if v.name() == 'InstallDate':
                                    os_dic['InstallDate'] = time.strftime('%a %b %d %H:%M:%S %Y (UTC)',
                                                                          time.gmtime(v.value()))
                                    self.signal9.emit("Install Date", os_dic['InstallDate'], "SOFTWARE>"+prod_info)
                                if v.name() == 'RegisteredOrganization':
                                    os_dic['RegisteredOrganization'] = v.value()
                                    self.signal9.emit("Registered Org", os_dic['RegisteredOrganization'], "SOFTWARE>"+prod_info)
                                if v.name() == 'RegisteredOwner':
                                    os_dic['RegisteredOwner'] = v.value()
                                    self.signal9.emit("Registered Owner", os_dic['RegisteredOwner'], "SOFTWARE>"+prod_info)
                                if v.name() == 'SystemRoot':
                                    os_dic['SystemRoot'] = v.value()
                                    self.signal9.emit("System Root", os_dic['SystemRoot'], "SOFTWARE>"+prod_info)
                        except Exception as ee:
                            print("An Error Occured on SOFTWARE File " + str(ee))
                    self.signal6.emit(starter_count)
            f.close()
        text_out = "Total Files Found: " + str(starter_count)
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        for k, v in sorted(ext_counts.items(), key=lambda p: p[1], reverse=True):
            submit = (k, str(v))
            self.signal8.emit(submit)
        text_out = "Filtering Results and Checking File Headers -- Building Database"
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        try:
            sqliteConnection = sqlite3.connect(db_path)
            cursor = sqliteConnection.cursor()
        except sqlite3.Error as error:
            text_out = "Failed to connect with sqlite3 database - " + str(error)
            self.signal7.emit("{0:<12}{1}".format(log, text_out))
        try:
            file_table = """ CREATE TABLE files_to_check (
                        FileName VARCHAR(255),
                        Extension VARCHAR(255),
                        FileSize VARCHAR(21),
                        Created_Time VARCHAR(75), 
                        Mod_Time VARCHAR(75), 
                        Access_Time VARCHAR(75),                                               
                        Version VARCHAR(75),
                        File_Path VARCHAR(255),
                        MD5 VARCHAR(75),
                        SHA1 VARCHAR(90)
                    ); """
            cursor.execute(file_table)
            text_out = "Datebase and tables created successfully"
            self.signal7.emit("{0:<12}{1}".format(log, text_out))
            text_out = "Applying filters and scanning file headers"
            self.signal7.emit("{0:<12}{1}".format(log, text_out))
        except sqlite3.OperationalError as OE:
            text_out = str(OE) + " ---  TABLE ALREADY EXISTS"
            self.signal7.emit("{0:<12}{1}".format(log, text_out))
        with open(report_loc + "\\temp\\DONT_MODIFY.temp", "r") as f:
            for item in f.readlines():
                file_path = item.rstrip()
                try:
                    file_size = os.path.getsize(file_path)
                    try:
                        file_name = os.path.basename(file_path)
                        file_name, extension = os.path.splitext(file_name)
                        if file_size > min_size and file_size < max_size:
                            m_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                            a_time = datetime.datetime.fromtimestamp(os.path.getatime(file_path))
                            c_time = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
                            if (m_time > start_date and m_time < end_date) or \
                                    (c_time > start_date and c_time < end_date):
                                    # (a_time > start_date and a_time < end_date) or\
                                with open(file_path, 'rb') as in_file:
                                    binary_header = in_file.read(2)
                                    file_header = b2a_hex(binary_header).decode()
                                    if file_header == sig:
                                        in_file.seek(0, 0)
                                        try:
                                            cursor.execute("""INSERT INTO files_to_check 
                                            (FileName, Extension, FileSize, Created_Time, Mod_Time, Access_Time, File_Path)
                                            VALUES 
                                            (?, ?, ?, ?, ?, ?, ?)""", (str(file_name), str(extension).replace(".",""), str(file_size), str(c_time), str(m_time), str(a_time), str(file_path)))
                                            sqliteConnection.commit()
                                            value_progress += 1
                                            header_match += 1
                                            self.signal2.emit(value_progress)
                                            self.signal3.emit(str(header_match) + D + str(skip_count) + D + str(
                                                error_count) + D + str(other_count))
                                        except sqlite3.Error as error:
                                            return
                                            # print(str(error))
                                    else:
                                        skip_count += 1
                                        value_progress += 1
                            else:
                                skip_count += 1
                                value_progress += 1
                        else:
                            skip_count += 1
                            value_progress += 1
                    except OSError or PermissionError as op:
                        error_count += 1
                        print(str(op))
                        pass
                    except Exception as ee:
                        other_count += 1
                        print(str(ee))

                        pass
                except ZeroDivisionError:
                    skip_count += 1
                except OSError:
                    error_count += 1
                except PermissionError:
                    error_count += 1
                self.signal2.emit(value_progress)
                self.signal3.emit(str(header_match) + D + str(skip_count) + D + str(error_count) + D + str(other_count))
            f.close()
        # os.remove(report_loc + "\\temp\\files" + str(time_now) + ".temp")

        self.signal2.emit(value_progress)
        self.signal3.emit(str(header_match) + D + str(skip_count) + D + str(error_count) + D + str(other_count))
        text_out = "Files Checked Total " + str(value_progress)
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        text_out = "File Matches added to the Database: " + str(header_match)
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        text_out = "*You may review output in the Analyze Tab"
        self.signal7.emit("{0:<12}{1}".format(log, text_out))
        text_out = "Starting Hashing Functions..."
        self.signal7.emit("{0:<12}{1}".format(log, text_out))

        cursor.execute("SELECT * FROM files_to_check")  # execute a simple SQL select query
        jobs = cursor.fetchall()  # get all the results from the above query
        to_proceess = len(jobs)
        self.signal6.emit(len(jobs))
        value_progress = 0
        go = 0
        hits_list = []
        with open(report_path, "a") as report_out:
            report_out.write("FileName,Extension,FileSize,CreatedTime,ModifiedTime,LastAccessed,Version,FilePath,MD5,SHA1,\n")
            for file in jobs:
                file_name = str(file[0])
                file_ext = str(file[1])
                file_size = str(file[2])
                file_created_time = str(file[3])
                file_mod_time = str(file[4])
                file_access_time = str(file[5])
                file_ver = str(file[6])
                file_path = str(file[7])
                file_md5 = str(file[8])
                file_sha1 = str(file[9])
                if os.path.isfile(file_path):
                    with open(file_path, "rb") as in_file:
                        md5 = hashlib.md5()
                        sha1 = hashlib.sha1()
                        block_size = 2 ** 20
                        while True:
                            data = in_file.read(block_size)
                            if not data:
                                break
                            md5.update(data)
                            sha1.update(data)
                        md5_hash = md5.hexdigest()
                        sha1_hash = sha1.hexdigest()
                    # with open(good_loc + sha1_hash[0:2] + "\\" + sha1_hash[0:2] + ".txt", 'r') as look_file:
                    #     for line in look_file.readlines():
                    #         if sha1_hash.lower() == line.lower().rstrip():
                    #             go = 0
                    #             nsrl_skip += 1
                    #             print("SKIP ** NSRL HIT FOUND - " + sha1_hash.lower() + " - " + file_path)
                    #             pass
                    #         else:
                    #             go = 1
                    # if go == 1:
                        try:
                            File_information = GetFileVersionInfo(file_path, "\\")
                            ms_file_version = File_information['FileVersionMS']
                            ls_file_version = File_information['FileVersionLS']
                            output = [str(HIWORD(ms_file_version)), str(LOWORD(ms_file_version)),
                                      str(HIWORD(ls_file_version)), str(LOWORD(ls_file_version))]
                            file_ver = str(".".join(output))
                        except:
                            # print("Error on Version Number Try - File Number: " + str(value_progress))
                            pass
                        try:
                            cursor.execute("""
                            update files_to_check set MD5 = ?, SHA1 = ?, Version = ? where File_Path = ?
                            """, (md5_hash, sha1_hash, str(version), file_path))
                            sqliteConnection.commit()
                        except sqlite3.Error as sqlE:
                            return
                            # print(str(sqlE))
                        stat_update = str(file_name +
                                          D + str(file_ext) +
                                          D + str(file_size) +
                                          D + str(file_created_time) +
                                          D + str(file_mod_time) +
                                          D + str(file_access_time) +
                                          D + str(file_ver) +
                                          D + str(file_path) +
                                          D + md5_hash +
                                          D + sha1_hash)
                        self.signal1.emit(stat_update)
                        # "FileName,Extension,FileSize,CreatedTime,ModifiedTime,LastAccessed,Version,FilePath,MD5,SHA1
                        report_out.write(file_name +
                                          ',' + file_ext +
                                          ',' + str(file_size) +
                                          ',' + str(file_created_time) +
                                          ',' + str(file_mod_time) +
                                          ',' + str(file_access_time) +
                                          ',' + str(file_ver) +
                                          ',' + file_path +
                                          ',' + md5_hash +
                                          ',' + sha1_hash + "\n")
                        for item in keyword_list:
                            if item == "":
                                pass
                            else:
                                if item.lower() in file_name.lower():
                                    if str(file_path.lower()) in hits_list:
                                        pass
                                    else:
                                        self.signal5.emit(str(stat_update) + "::Keyword - FileName")
                                        hits_list.append(str(file_path.lower()))
                                if item.lower() == md5_hash.lower():
                                    if str(file_path.lower()) in hits_list:
                                        pass
                                    else:
                                        self.signal5.emit(str(stat_update) + "::Keyword - MD5")
                                        hits_list.append(str(file_path.lower()))
                                if item.lower() == sha1_hash.lower():
                                    if str(file_path.lower()) in hits_list:
                                        pass
                                    else:
                                        self.signal5.emit(str(stat_update) + "::Keyword - SHA1")
                                        hits_list.append(str(file_path.lower()))
                                if str(item) == str(file_size):
                                    if str(file_path.lower()) in hits_list:
                                        pass
                                    else:
                                        self.signal5.emit(str(stat_update) + "::Keyword - File Size")
                                        hits_list.append(str(file_path.lower()))
                        for rat in rat_list:
                            if item == "":
                                pass
                            elif str(file_path.lower()) in hits_list:
                                pass
                            else:
                                if rat.lower() in file_name.lower():
                                    self.signal5.emit(str(stat_update) + "::RAT Name")
                                    hits_list.append(str(file_path.lower()))
                        # print(hits_list)
                        value_progress += 1
                        self.signal2.emit(float(value_progress))
                else:
                    # print("File path not found : " + str(file_path))
                    value_progress += 1
                    self.signal2.emit(value_progress)


        # for hive in registry_paths:
        #     path = target_drive_letter + hive
        #     try:
        #         if os.path.isfile(path):
        #             shutil.copy(target_drive_letter + hive, report_loc + "\\Data\\Registry\\")
        #             print("Registry File Found -" + str(file_path))
        #             print("File Copied to " + report_loc + "\\Data\\Registry\\")
        #             """
        #             MAYBE DO SOME MORE WITH THE REGISTRY FILES HERE
        #             %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        #             """
        #         else:
        #             print("REGISTRY - DOES NOT EXIST : " + path)
        #     except PermissionError as pe:
        #         print("Permission Error, OS is currently using or has locked : " + path)
        #         pass

        self.signal2.emit(value_progress)

        text_out = "Hashing Completed - Database is Updated"
        self.signal7.emit("{0:<12}{1}".format(log, text_out))

        # output_hl = '<a href="{}">CSV_Report</a>'.format(report_loc + "/data/")
        # text_out = ("CSV Report created: " + output_hl)
        self.signal7.emit("LOG:        " + '<a href="{}">CSV Report Location</a>'.format(report_loc + "/data/"))

        # self.signal7.emit


        # log = "NSRL Items Skipped  " + (str(nsrl_skip))
        # self.signal7.emit("LOG:{0:8}".format(log))
        execution_time = (time.time() - start_time) / 60
        self.signal4.emit("SCRIPT COMPLETED: " +
                          D + str(header_match) +
                          D + str(skip_count) +
                          D + str(error_count) +
                          D + str(other_count) +
                          D + str(round(execution_time, 2)) +
                          D + str(target_loc))
        cursor.close()
        report_out.close()

    def pull_key(self, reg_file, key_path):
        global registry
        registry = Registry.Registry(reg_file)
        key = registry.open(key_path)
        key_dic = {}
        for v in key.values():
            key_dic[v.name()] = v.value()
        return key_dic

    def control_set_check(self, sys_reg):
        registry = Registry.Registry(sys_reg)
        key = registry.open("Select")
        for v in key.values():
            if v.name() == "Current":
                return v.value()


class UI(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("UpFront.ui", self)
        self.setStyleSheet(qdarktheme.load_stylesheet())
        self.settings = QSettings('settings.ini', QSettings.IniFormat)
        self.settings.setFallbacksEnabled(False)
        self.setWindowTitle("UpFront")
        self.restoreGeometry(self.settings.value('geometry', bytes()))
        self.settings.setValue("geometry", self.saveGeometry())
        self.splitter.restoreState(self.settings.value('splitter', bytes()))
        self.splitter_2.restoreState(self.settings.value('splitter_2', bytes()))
        self.splitter_3.restoreState(self.settings.value('splitter_3', bytes()))
        try:
            is_admin = (os.getuid() == 0)
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            self.label_admin.setText('<font color="green">Current Privelage:  Admin/Root</font>')
        else:
            self.label_admin.setText('<font color="maroon">Current Privelage:  User Only</font>')
        self.actionExit.triggered.connect(self.closeEvent)
        self.action_darkMode.triggered.connect(self.darkmode)
        self.action_lightMode.triggered.connect(self.lightmode)
        self.pushButton_target.clicked.connect(self.get_dir)
        self.pushButton_output.clicked.connect(self.get_dir)
        self.pushButton_keyword.clicked.connect(self.get_file)
        self.pushButton_start.clicked.connect(self.hash_stuff)
        self.hash_thread = HashThread()
        self.hash_thread.signal1.connect(self.finished_hash)
        self.hash_thread.signal2.connect(self.hash_progress)
        self.hash_thread.signal3.connect(self.update_counts)
        self.hash_thread.signal4.connect(self.completed)
        self.hash_thread.signal5.connect(self.match_found)
        self.hash_thread.signal6.connect(self.updatebar)
        self.hash_thread.signal7.connect(self.log_status)
        self.hash_thread.signal8.connect(self.ext_status)
        self.hash_thread.signal9.connect(self.reg_status)
        self.pushButton_getStrings.clicked.connect(self.run_strings)
        self.strings_thread = RunStrings()
        self.strings_thread.signal1.connect(self.output_strings)
        self.strings_thread.signal2.connect(self.strings_progress)
        self.strings_thread.signal3.connect(self.notable_string)
        self.strings_thread.signal3.connect(self.b64_strings)
        self.model1 = QFileSystemModel()
        self.model1.setFilter(QDir.Filters(QDir.Dirs | QDir.Hidden | QDir.Files))
        self.model1.sort(0, Qt.DescendingOrder)
        self.treeView.setModel(self.model1)
        self.treeView.setEnabled(False)
        self.pushButton_cert_start.clicked.connect(self.run_get_certs)
        self.certs_thread = GetCerts()
        self.certs_thread.signal1.connect(self.cert_update)
        self.certs_thread.signal2.connect(self.cert_progress)
        self.pushButton_pe_start.clicked.connect(self.run_pe_data)
        self.pe_data_thread = PeData()
        self.pe_data_thread.signal.connect(self.output_pe_data)
        self.pe_data_thread.signal1.connect(self.output_pe_data1)
        self.pe_data_thread.signal2.connect(self.output_pe_data2)
        self.pe_data_thread.signal3.connect(self.output_pe_data3)
        self.pe_data_thread.signal4.connect(self.output_pe_data4)
        self.pe_data_thread.signal5.connect(self.output_pe_data5)
        self.pe_data_thread.signal6.connect(self.output_pe_data6)
        self.pe_data_thread.signal7.connect(self.output_pe_data7)
        self.pe_data_thread.signal8.connect(self.output_pe_data8)
        self.pe_data_thread.signal9.connect(self.output_pe_data9)
        self.pe_data_thread.signal10.connect(self.output_pe_data10)
        self.pe_data_thread.signal11.connect(self.output_pe_data11)
        self.pe_data_thread.signal12.connect(self.output_pe_data12)
        self.pe_data_thread.signal13.connect(self.output_pe_data13)
        self.pe_data_thread.signal14.connect(self.output_pe_data14)
        self.pe_data_thread.signal15.connect(self.output_pe_data15)
        self.pe_data_thread.signal16.connect(self.output_pe_data16)
        self.pe_data_thread.signal17.connect(self.output_pe_data17)
        self.pe_data_thread.signal18.connect(self.output_pe_data18)
        self.pe_data_thread.signal19.connect(self.pe_progress)
        self.report_thread = CreateReports()
        self.report_thread.signal1.connect(self.report_stuff)
        self.pushButton_vtLookup.clicked.connect(self.run_vt)
        self.vt_thread = VtLookup()
        self.vt_thread.signal1.connect(self.output_vt)     # Update left table, main info
        self.vt_thread.signal3.connect(self.output2_vt)    # Update right table, extra info

        self.pushButton_peTarget.clicked.connect(self.get_file)
        self.pushButton_peSource.clicked.connect(self.get_file)
        self.pushButton_peCompare.clicked.connect(self.run_pe_compare)
        self.pe_compare_thread = PeCompare()
        self.pe_compare_thread.signal1.connect(self.output_pe_comp)
        self.pe_compare_thread.signal2.connect(self.output_pe_labels)
        self.pe_compare_thread.signal3.connect(self.output_pe_progress)


        self.progressBar = QProgressBar()
        self.statusBar().addPermanentWidget(self.progressBar)
        self.progressBar.setGeometry(0, 1, 450, 10)
        self.progressBar.setMaximumWidth(800)
        self.progressBar.setValue(0)
        self.progressBar.setFont(QFont('Arial', 11))
        self.progressBar.setFormat('Waiting...')
        self.dateTimeEdit_end.setDateTime(QDateTime.currentDateTime())
        current_year = int(self.dateTimeEdit_end.dateTime().toString("yyyy"))
        current_month = int(self.dateTimeEdit_end.dateTime().toString("MM"))
        current_day = int(self.dateTimeEdit_end.dateTime().toString("dd"))
        current_hour = int(self.dateTimeEdit_end.dateTime().toString("hh"))
        current_min = int(self.dateTimeEdit_end.dateTime().toString("mm"))
        current_sec = int(self.dateTimeEdit_end.dateTime().toString("ss"))
        dt = QDateTime(current_year - 1, current_month, current_day, current_hour, current_min, current_sec)
        self.dateTimeEdit_start.setDateTime(dt)
        self.stackedWidget_all.setCurrentIndex(0)
        self.stackedWidget_sub.setCurrentIndex(1)
        self.tableWidget_2.cellClicked.connect(self.cell_was_clicked)
        self.tableWidget_certs.cellClicked.connect(self.cell_was_clicked2)
        self.button_selected = "border-style: solid;border-color: #5dadbd; border-width: 3px; border-radius: 3px;"
        self.button_unselected = "border-style: solid;border-color: #f9f8dd; border-width: 1px; border-radius: 1px;"
        self.btn_change_sel = {'pushButton_details': {self.pushButton_details: 0},
                               'pushButton_exe': {self.pushButton_exe: 1},
                               'pushButton_help': {self.pushButton_help: 2}}

        self.btn_change_sel2 = {'pushButton_strings': {self.pushButton_strings: 0},
                                'pushButton_keywords': {self.pushButton_keywords: 1},
                                'pushButton_osint': {self.pushButton_osint: 2},
                                'pushButton_certs': {self.pushButton_certs: 3},
                                'pushButton_tree': {self.pushButton_tree: 4},
                                'pushButton_breakout': {self.pushButton_breakout: 5},
                                'pushButton_compare': {self.pushButton_compare: 6}
                                }
        self.pushButton_keywords.setStyleSheet(self.button_selected)
        self.pushButton_details.setStyleSheet(self.button_selected)
        for item in self.btn_change_sel.keys():
            for button in self.btn_change_sel[item].keys():
                button.clicked.connect(self.btn_style_change)
        for item in self.btn_change_sel2.keys():
            for button in self.btn_change_sel2[item].keys():
                button.clicked.connect(self.btn_style_change2)
        self.button_combine = [self.btn_change_sel]
        self.button_combine2 = [self.btn_change_sel2]
        self.tableWidget.installEventFilter(self)
        self.pushButton_start.setEnabled(False)
        self.lineEdit_re.textChanged.connect(self.re_check)
        self.textEdit_strings_3.clear()
        self.show()

    def darkmode(self):
        # self.setStyleSheet(qdarktheme.setup_theme("dark"))
        self.setStyleSheet(qdarktheme.load_stylesheet("dark"))
        self.textBrowser_vt.setFont(QFont('Consolas', 12))
        self.textBrowser_vt2.setFont(QFont('Consolas', 12))
        self.textBrowser_basicInfo.setFont(QFont('Consolas', 12))
        self.textBrowser_header.setFont(QFont('Consolas', 12))
        self.textBrowser_dataDir.setFont(QFont('Consolas', 12))
        self.textBrowser_imports.setFont(QFont('Consolas', 12))
        self.textBrowser_sections.setFont(QFont('Consolas', 12))
        self.textBrowser_Symbols.setFont(QFont('Consolas', 12))
        self.textBrowser_tls.setFont(QFont('Consolas', 12))
        self.textBrowser_Export.setFont(QFont('Consolas', 12))
        self.textBrowser_debug.setFont(QFont('Consolas', 12))
        self.textBrowser_signature.setFont(QFont('Consolas', 12))
        self.textBrowser_richHeader.setFont(QFont('Consolas', 12))
        self.textBrowser_resources.setFont(QFont('Consolas', 12))
        self.textBrowser_loadConfig.setFont(QFont('Consolas', 12))
        self.textBrowser_Construc.setFont(QFont('Consolas', 12))
        self.textBrowser_function.setFont(QFont('Consolas', 12))
        self.textBrowser_except.setFont(QFont('Consolas', 12))
        self.textBrowser_delayImport.setFont(QFont('Consolas', 12))
        self.textBrowser_function.setFont(QFont('Consolas', 12))

    def lightmode(self):
        # self.setStyleSheet(qdarktheme.setup_theme("light"))
        self.setStyleSheet(qdarktheme.load_stylesheet("light"))
        self.textBrowser_vt.setFont(QFont('Consolas', 12))
        self.textBrowser_vt2.setFont(QFont('Consolas', 12))
        self.textBrowser_basicInfo.setFont(QFont('Consolas', 12))
        self.textBrowser_header.setFont(QFont('Consolas', 12))
        self.textBrowser_dataDir.setFont(QFont('Consolas', 12))
        self.textBrowser_imports.setFont(QFont('Consolas', 12))
        self.textBrowser_sections.setFont(QFont('Consolas', 12))
        self.textBrowser_Symbols.setFont(QFont('Consolas', 12))
        self.textBrowser_tls.setFont(QFont('Consolas', 12))
        self.textBrowser_Export.setFont(QFont('Consolas', 12))
        self.textBrowser_debug.setFont(QFont('Consolas', 12))
        self.textBrowser_signature.setFont(QFont('Consolas', 12))
        self.textBrowser_richHeader.setFont(QFont('Consolas', 12))
        self.textBrowser_resources.setFont(QFont('Consolas', 12))
        self.textBrowser_loadConfig.setFont(QFont('Consolas', 12))
        self.textBrowser_Construc.setFont(QFont('Consolas', 12))
        self.textBrowser_function.setFont(QFont('Consolas', 12))
        self.textBrowser_except.setFont(QFont('Consolas', 12))
        self.textBrowser_delayImport.setFont(QFont('Consolas', 12))
        self.textBrowser_function.setFont(QFont('Consolas', 12))

    def run_pe_compare(self):
        source_path = self.lineEdit_peSource.text()
        target_path = self.lineEdit_pe_target.text()
        if source_path == "" or target_path == "":
            QMessageBox.information(self, "Warning-", "You did not select a Source or Target File Yet")
            return
        elif os.path.exists(source_path) == False or os.path.exists(target_path) == False:
            QMessageBox.information(self, "Warning-", "YYour Target File does not seem to exist...")
            return
        else:
            self.pe_compare_thread.pe_compare_data = source_path, target_path
            self.pe_compare_thread.start()

    def output_pe_comp(self, result):
        print(str(result))
        self.textBrowser_comparison.append(str(result))

    def output_pe_progress(self, result, string):
        self.progressBar_compare.setValue(int(result))
        self.progressBar_compare.setFormat(str(string))

    def output_pe_labels(self, result):
        print(str(result))
        source_num = result[0]
        target_num = result[1]
        same_count = result[2]
        sim_count = result[3]
        scoring = result[4]
        self.label_compare.setText(scoring)
        self.label_src_tot_2.setText("Source Comps: " + str(source_num))
        self.label_targ_tot.setText("Target Comps: " + str(target_num))
        self.label_idenitcal.setText("Same: " + str(same_count))
        self.label_similiar.setText("Similiar: " + str(sim_count))
        self.label_compare.setStyleSheet("background-color: lightgreen")


    def re_check(self):
        re_sample = self.lineEdit_re.text()
        if re_sample == "":
            self.label_reCheck.setText('<font color="white">NO ENTRY</font>')
            pass
        else:
            try:
                re.compile(re_sample)
                self.label_reCheck.setText('<font color="green">VALID</font>')
            except re.error:
                self.label_reCheck.setText('<font color="red">INVALID</font>')
                return

    def reg_status(self, desc, data, key):
        rowPosition = self.tableWidget_registry.rowCount()
        self.tableWidget_registry.insertRow(rowPosition)
        self.tableWidget_registry.setItem(rowPosition, 0, QTableWidgetItem(desc))
        self.tableWidget_registry.setItem(rowPosition, 1, QTableWidgetItem(data))
        self.tableWidget_registry.setItem(rowPosition, 2, QTableWidgetItem(key))
        self.tableWidget_registry.resizeColumnsToContents()
        self.tableWidget_registry.scrollToBottom()

    def eventFilter(self, source, event):
        if event.type() == QEvent.ContextMenu and source is self.tableWidget:
            menu = QMenu()
            # menu.addAction("Lookup on VT")
            # menu.addAction("Run Strings")
            # menu.addAction("PE Data")
            menu.addAction("Export File and Report")
            if menu.exec_(event.globalPos()):
                item = source.itemAt(event.pos())
                if item == None:
                    print("None at object")
                else:
                    print(item.text())
                    row = self.tableWidget.currentRow()
                    try:
                        file_path = self.tableWidget.item(row, 7).text()
                        if file_path == None:
                            print("No File Path available for selection")
                            return
                        else:
                            out_loc = QFileDialog.getExistingDirectory(self, "Select a Location", "")
                            if out_loc == "":
                                QMessageBox.information(self, "Warning-", "You did not select a Directory ...")
                                return
                            else:
                                if os.path.exists(out_loc):
                                    if os.path.exists(out_loc + "/Upfront_Reports"):
                                        pass
                                    else:
                                        os.mkdir(out_loc + "/Upfront_Reports/")
                                    file_name = self.tableWidget.item(row, 0).text()
                                    file_ext = self.tableWidget.item(row, 1).text()
                                    file_size = str(self.tableWidget.item(row, 2).text())
                                    created = str(self.tableWidget.item(row, 3).text())
                                    modified = str(self.tableWidget.item(row, 4).text())
                                    accessed = str(self.tableWidget.item(row, 5).text())
                                    version = str(self.tableWidget.item(row, 6).text())
                                    file_path = self.tableWidget.item(row, 7).text()
                                    md5 = self.tableWidget.item(row, 8).text()
                                    sha1 = self.tableWidget.item(row, 9).text()
                                    if version == None or "None":
                                        self.report_thread.report_items = file_name, file_ext, file_size, created, modified, accessed, "None", file_path, md5, sha1, out_loc
                                    else:
                                        self.report_thread.report_items = file_name, file_ext, file_size, created, modified, accessed, "None", file_path, md5, sha1, out_loc
                                    self.report_thread.start()



                    except AttributeError as ae:
                        print(str(ae))
            return True
        return super().eventFilter(source, event)

    def report_stuff(self):
        report_stuff

    def cell_was_clicked(self):
        row = self.tableWidget_2.currentRow()
        sha_check = self.tableWidget_2.item(row, 10).text()
        items = self.tableWidget.findItems(sha_check, Qt.MatchContains)
        if items:  # we have found something
            item = items[0]  # take the first
            self.tableWidget.setCurrentItem(item)
            row = self.tableWidget.currentRow()
            self.tableWidget.setCurrentItem(self.tableWidget.item(row, 0))

    def cell_was_clicked2(self):
        row = self.tableWidget_certs.currentRow()
        sha_check = self.tableWidget_certs.item(row, 5).text()
        items = self.tableWidget.findItems(sha_check, Qt.MatchContains)
        if items:  # we have found something
            item = items[0]  # take the first
            self.tableWidget.setCurrentItem(item)
            row = self.tableWidget.currentRow()
            self.tableWidget.setCurrentItem(self.tableWidget.item(row, 0))

    def btn_style_change(self):
        sending_button = self.sender()
        check_sender = str(sending_button.objectName())
        if check_sender in self.button_combine[0].keys():
            dict_x = self.btn_change_sel
            stack_x = self.stackedWidget_all
        for sender_name in dict_x.keys():
            if check_sender == sender_name:
                for btn_item, stack_idx in dict_x[sender_name].items():
                    btn_item.setStyleSheet(self.button_selected)
                    stack_x.setCurrentIndex(stack_idx)
            if check_sender != sender_name:
                for btn_item2 in dict_x[sender_name].keys():
                    btn_item2.setStyleSheet(self.button_unselected)

    def btn_style_change2(self):
        sending_button = self.sender()
        check_sender = str(sending_button.objectName())
        if check_sender in self.button_combine2[0].keys():
            dict_x = self.btn_change_sel2
            stack_x = self.stackedWidget_sub
        for sender_name in dict_x.keys():
            if check_sender == sender_name:
                for btn_item, stack_idx in dict_x[sender_name].items():
                    btn_item.setStyleSheet(self.button_selected)
                    stack_x.setCurrentIndex(stack_idx)
            if check_sender != sender_name:
                for btn_item2 in dict_x[sender_name].keys():
                    btn_item2.setStyleSheet(self.button_unselected)

    def run_get_certs(self):
        output = self.lineEdit_output.text()
        try:
            # self.tableWidget_certs.clear()
            self.certs_thread.certs_data = output
            self.certs_thread.start()
        except AttributeError as ae:
            pass
            # print(str(ae) + " -- ERROR")
        self.pushButton_cert_start.setEnabled(False)

    def cert_update(self, result):
        file_name = result[0]
        status = result[1]
        signer = result[2]
        auth_hash = result[3]
        path = result[4]
        sha1_hash = result[5]
        rowPosition = self.tableWidget_certs.rowCount()
        self.tableWidget_certs.insertRow(rowPosition)
        self.tableWidget_certs.setItem(rowPosition, 0, QTableWidgetItem(str(file_name)))
        self.tableWidget_certs.setItem(rowPosition, 1, QTableWidgetItem(str(status)))
        self.tableWidget_certs.setItem(rowPosition, 2, QTableWidgetItem(str(signer)))
        self.tableWidget_certs.setItem(rowPosition, 3, QTableWidgetItem(str(auth_hash)))
        self.tableWidget_certs.setItem(rowPosition, 4, QTableWidgetItem(str(path)))
        self.tableWidget_certs.setItem(rowPosition, 5, QTableWidgetItem(str(sha1_hash)))
        self.tableWidget_certs.resizeColumnsToContents()
        self.tableWidget_certs.scrollToBottom()

    def cert_progress(self, result):
        self.progressBar_certs.setValue(int(result))

    def run_pe_data(self):
        try:
            # self.textBrowser_file_sig.clear()
            row = self.tableWidget.currentRow()
            file_path = self.tableWidget.item(row, 7).text()
            file_sha1 = self.tableWidget.item(row, 9).text()
            if self.checkBox_fuzzy.isChecked() == True:
                self.pe_data_thread.pe_data = file_path, file_sha1, "YES"
                self.pe_data_thread.start()
            else:
                self.pe_data_thread.pe_data = file_path, file_sha1, "NO"
                self.pe_data_thread.start()
        except AttributeError as ae:
            print(str(ae))
            pass
        except Exception as ee:
            print(str(ee))
            pass
            # print(str(ae) + " -- ERROR")
        # self.pushButton_getStrings.setEnabled(False)

    def output_pe_data(self, result):
        if result == "GO":
            self.textBrowser_basicInfo.clear()
            self.textBrowser_dataDir.clear()
            self.textBrowser_header.clear()
            self.textBrowser_imports.clear()
            self.textBrowser_reloc.clear()
            self.textBrowser_sections.clear()
            self.textBrowser_Symbols.clear()
            self.textBrowser_tls.clear()
            self.textBrowser_Export.clear()
            self.textBrowser_debug.clear()
            self.textBrowser_signature.clear()
            self.textBrowser_richHeader.clear()
            self.textBrowser_resources.clear()
            self.textBrowser_loadConfig.clear()
            self.textBrowser_Construc.clear()
            self.textBrowser_function.clear()
            self.textBrowser_except.clear()
            self.textBrowser_delayImport.clear()
        else:
            pass

    def output_pe_data1(self, result):
        self.textBrowser_basicInfo.append(str(result))
    def output_pe_data2(self, result):
        self.textBrowser_dataDir.append(str(result))
    def output_pe_data3(self, result):
        self.textBrowser_header.append(str(result))
    def output_pe_data4(self, result):
        self.textBrowser_imports.append(str(result))
    def output_pe_data5(self, result):
        self.textBrowser_reloc.append(str(result))
    def output_pe_data6(self, result):
        self.textBrowser_sections.append(str(result))
    def output_pe_data7(self, result):
        self.textBrowser_Symbols.append(str(result))
    def output_pe_data8(self, result):
        self.textBrowser_tls.append(str(result))
    def output_pe_data9(self, result):
        self.textBrowser_Export.append(str(result))
    def output_pe_data10(self, result):
        self.textBrowser_debug.append(str(result))
    def output_pe_data11(self, result):
        self.textBrowser_signature.append(str(result))
    def output_pe_data12(self, result):
        self.textBrowser_richHeader.append(str(result))
    def output_pe_data13(self, result):
        self.textBrowser_resources.append(str(result))
    def output_pe_data14(self, result):
        self.textBrowser_loadConfig.append(str(result))
    def output_pe_data15(self, result):
        self.textBrowser_Construc.append(str(result))
    def output_pe_data16(self, result):
        self.textBrowser_function.append(str(result))
    def output_pe_data17(self, result):
        self.textBrowser_except.append(str(result))
    def output_pe_data18(self, result):
        self.textBrowser_delayImport.append(str(result))

    def pe_progress(self, result, string):
        self.progressBar_peData.setValue(int(result))
        self.progressBar_peData.setFormat(str(string))

    def run_vt(self):
        key = self.lineEdit_api_key.text().lower().rstrip()
        key_len = len(key)
        if (key == "") or (key == None) or (len(key) != 64):
            QMessageBox.information(self, "Missing Info", "You need to enter a valid 64 Character API key first\n\n" +
                                                          "https://www.virustotal.com/gui/my-apikey")
        else:
            try:
                self.textBrowser_vt.clear()
                self.textBrowser_vt2.clear()
                row = self.tableWidget.currentRow()
                file_sha1 = self.tableWidget.item(row, 9).text().rstrip()
                api = self.lineEdit_api_key.text().lower().rstrip()
                self.vt_thread.vt_hash = file_sha1, api
                # print("BOUT TO START THREAD: " + file_sha1 + "  -  " + api)
                self.vt_thread.start()
            except AttributeError as a:
                # print(str(a))
                QMessageBox.information(self, "Woah...", "You need to select a file in the 4d5a Table first")
                return

    def output_vt(self, result):
        self.textBrowser_vt.append(str(result))

    def output2_vt(self, result):
        self.textBrowser_vt2.append(str(result))

    def finished_vt(self):
        self.pushButton_vtLookup.setEnabled(True)

    def b64_strings(self, results):
        string = results[0]
        base64 = results[1]
        self.textEdit_strings_3.clear()
        self.textEdit_strings_3.append(str(string))
        self.textEdit_strings_3.append(str(base64))

    def run_strings(self):
        try:
            self.textEdit_strings.clear()
            self.textEdit_strings_2.clear()
            self.textEdit_strings_3.clear()
            row = self.tableWidget.currentRow()
            file_path = self.tableWidget.item(row, 7).text()
            file_size = self.tableWidget.item(row, 2).text()
            string_size = self.lineEdit_string_size.text()
            custom_re = re_sample = self.lineEdit_re.text()
            try:
                int(string_size)
            except:
                QMessageBox.information(self, "Need A Number", "Your String Minimum size is not a number")
            try:
                re.compile(custom_re)
            except re.error:
                QMessageBox.information(self, "Custom RegEx Invalid", "Check your entry or clear Custom RegEx testbox")
                return
            if string_size == '':
                string_size = 4
            else:
                self.strings_thread.file_strings = file_path, string_size, custom_re
                self.strings_thread.start()
                self.pushButton_getStrings.setEnabled(False)
        except AttributeError as a:
            QMessageBox.information(self, "Woah...", "You need to select a file in the output table first")
            self.pushButton_getStrings.setEnabled(True)
            return
        self.pushButton_getStrings.setEnabled(False)

    def notable_string(self, result):
        self.textEdit_strings_2.append(str(result))

    def strings_progress(self, result):
        if result == 100:
            self.pushButton_getStrings.setEnabled(True)
            self.progressBar_strings.setValue(int(result))
        else:
            self.progressBar_strings.setValue(int(result))

    def output_strings(self, result):
        self.textEdit_strings.append(str(result))

    def get_dir(self, button_name):
        sender = self.sender()
        directory = QFileDialog.getExistingDirectory(self, "Select a directory", "")  #
        if directory == "":
            QMessageBox.information(self, "Warning-", "You did not select a Directory ...")
            return
        else:
            if os.path.exists(directory):
                if sender == self.pushButton_target:
                    self.lineEdit_target.setText(directory)
                    self.lineEdit_target.setReadOnly(True)
                    self.textBrowser_status.append("{0:<30}{1}".format("Target Directory Set:", directory))
                    if self.lineEdit_output.text() != "":
                        self.pushButton_start.setEnabled(True)
                elif sender == self.pushButton_output:
                    self.lineEdit_output.setText(directory)
                    self.lineEdit_output.setReadOnly(True)
                    self.textBrowser_status.append("{0:<30}{1}".format("Output Directory Set:", directory))
                    if self.lineEdit_target.text() != "":
                        self.pushButton_start.setEnabled(True)
                else:
                    pass
                    # print("Directory Find error here somewhere....")
            else:self.textBrowser_status.append("ERROR: Your selected location does not appear to exist: " + directory)

    def get_file(self, button_name):
        sender = self.sender()
        if sender == self.pushButton_keyword:
            file = QFileDialog.getOpenFileName(self, "Select a File", "", "Text Files (*.txt)")
            if file[0] == "":
                QMessageBox.information(self, "Warning-", "You did not select a Keywords File ...")
                return
            else:
                if os.path.exists(file[0]):
                    self.lineEdit_keyword.setText(file[0])
                    self.lineEdit_target.setReadOnly(True)
                    self.textBrowser_status.append("{0:<30}{1}".format("Keyword List Set:", file[0]))
                else:
                    self.textBrowser_status.append("Your selected Keyword file does not appear to exist")
        elif sender == self.pushButton_peTarget:
            file = QFileDialog.getOpenFileName(self, "Select a File", "", "Any (*.*)")
            if file[0] == "":
                QMessageBox.information(self, "Warning-", "You did not select a DB File ...")
                return
            else:
                if os.path.exists(file[0]):
                    self.lineEdit_pe_target.setText(file[0])
        elif sender == self.pushButton_peSource:
            file = QFileDialog.getOpenFileName(self, "Select a File", "", "Any (*.*)")
            if file[0] == "":
                QMessageBox.information(self, "Warning-", "You did not select a DB File ...")
                return
            else:
                if os.path.exists(file[0]):
                    self.lineEdit_peSource.setText(file[0])
        else:
            pass

    def hash_stuff(self):
        target = self.lineEdit_target.text()
        output = self.lineEdit_output.text()
        keyword = self.lineEdit_keyword.text()
        min_size = self.lineEdit_min_file.text()
        max_size = self.lineEdit_max_file.text()
        start_time = self.dateTimeEdit_start.dateTime().toString("dd-MM-yyyy hh:mm:ss.zz")
        end_time = self.dateTimeEdit_end.dateTime().toString("dd-MM-yyyy hh:mm:ss.zz")
        if min_size == "":
            min_size == str(2048) # 2 KB
            self.textBrowser_status.append("No Min Size, Setting to Default: "+ str(min_size))
        else:
            try:
                min_size == int(min_size.replace(",","").replace(" ", "").strip())
            except ValueError as ve:
                self.textBrowser_status.append("***Minimum Size is not a number: " + str(min_size))
                return
        if max_size == "":
            max_size == str(102400000) # 100 MB
            self.textBrowser_status.append("No Max Size, Setting to Default: " + str(max_size))
        else:
            try:
                max_size == int(max_size.replace(",","").replace(" ", "").strip())
            except:
                self.textBrowser_status.append("***Maximum Size is not a number: " + str(max_size))
                return

        if int(max_size) <= int(min_size):
            self.textBrowser_status.append("***Your Maximum File Size is lower or equal to your Minimum Size ?!?")
            return

        if os.path.exists(target):
            if os.path.exists(output):
                self.textBrowser_status.append("{0:<30}{1}".format("Setting File Size Filter to:", (min_size  + " to " + max_size + " Bytes")))
                self.textBrowser_status.append("{0:<30}{1}".format("Setting Time Filter to:", (start_time + "  to  " + end_time)))
                self.textBrowser_status.append("-------  Main Script Starting ------- " + str(datetime.datetime.now()))
                reply = QMessageBox.question(self, 'Double Check...',
                                                   "Before starting, please review the information and confirm\n" +
                                             target + "\n" +
                                             output + "\n" +
                                             keyword + "\n" +
                                             min_size + "\n" +
                                             max_size + "\n" +
                                             start_time + "\n" +
                                             end_time + "\n"
                                             , QMessageBox.Yes, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.pushButton_start.setEnabled(False)
                    self.pushButton_target.setEnabled(False)
                    self.pushButton_output.setEnabled(False)
                    self.pushButton_keyword.setEnabled(False)
                    self.hash_thread.dir_to_hash = target, output, keyword, str(min_size), str(max_size), start_time, end_time
                    self.hash_thread.start()
                if reply == QMessageBox.No:
                    return
            else:
                self.textBrowser_status.append("Output Path does not exist")
                return
        else:
            self.textBrowser_status.append("Target Path does not exist")
            return

    def finished_hash(self, result):
        file_name = result.split(D)[0]
        file_ext = result.split(D)[1]
        file_size = result.split(D)[2]
        c_time = result.split(D)[3]
        m_time = result.split(D)[4]
        a_time = result.split(D)[5]
        file_ver = result.split(D)[6]
        file_path = result.split(D)[7]
        file_md5 = result.split(D)[8]
        file_sha1 = result.split(D)[9]
        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(file_name))
        self.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(file_ext))
        self.item = QTableWidgetItem()
        self.item.setData(Qt.DisplayRole, int(file_size))
        self.tableWidget.setItem(rowPosition, 2, self.item)
        self.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(str(c_time)))
        self.tableWidget.setItem(rowPosition, 4, QTableWidgetItem(str(m_time)))
        self.tableWidget.setItem(rowPosition, 5, QTableWidgetItem(str(a_time)))
        self.tableWidget.setItem(rowPosition, 6, QTableWidgetItem(file_ver))
        self.tableWidget.setItem(rowPosition, 7, QTableWidgetItem(file_path))
        self.tableWidget.setItem(rowPosition, 8, QTableWidgetItem(file_md5))
        self.tableWidget.setItem(rowPosition, 9, QTableWidgetItem(file_sha1))
        # self.tableWidget.resizeColumnsToContents()
        self.tableWidget.scrollToBottom()

    def update_counts(self, results):
        match_count = results.split(D)[0]
        skip_counts = results.split(D)[1]
        error_counts = results.split(D)[2]
        other_counts = results.split(D)[3]
        self.label_match_count.setText(" Header match Count:\t\t" + str(match_count) + "\t\t\t")
        self.label_skipped_count.setText("Total Files Skipped:\t" + str(skip_counts) + "\t\t\t")
        self.label_OS_error_count.setText("OS or Permission Errors:\t\t" + str(error_counts) + "\t\t\t")
        self.label_other_error_count.setText("Other Errors:\t\t" + str(other_counts) + "\t\t\t")

    def updatebar(self, total_files):
        self.progressBar.setFormat('Total Files Count: ' + str(total_files))
        self.progressBar.setMaximum(total_files)

    def hash_progress(self, result):
        self.progressBar.setValue(int(result))

    def log_status(self, text):
        self.textBrowser_status.append(str(text))
        # self.textBrowser_status.scrollToBottom()

    def ext_status(self, output):
        extension = output[0]
        ext_count = output[1]
        if extension == "":
            extension = "<No Ext>"
        item = QListWidgetItem("{0:>8}       {1:<}".format(ext_count, extension))
        self.listWidget_stats.addItem(item)

    def completed(self, results):
        # self.textBrowser_status.clear()
        some_text = results.split(D)[0]
        match_count = results.split(D)[1]
        skip_counts = results.split(D)[2]
        error_counts = results.split(D)[3]
        other_counts = results.split(D)[4]
        script_time = results.split(D)[5]
        directory = results.split(D)[6]
        self.textBrowser_status.append("\nMain Script Completed -- " + str(datetime.datetime.now()))
        self.textBrowser_status.append("Header Match Count     : " + str(match_count))
        self.textBrowser_status.append("Total Files Skipped    : " + str(skip_counts))
        self.textBrowser_status.append("OS/Permission Errors   : " + str(error_counts))
        self.textBrowser_status.append("Other Errors           : " + str(other_counts))
        self.textBrowser_status.append("Total Time             : " + str(script_time) + " Minutes\n\n")
        self.progressBar.setFormat('SCAN COMPLETE')
        self.progressBar.setValue(0)
        self.treeView.setEnabled(True)
        self.model1.setRootPath(directory)
        self.treeView.setRootIndex(self.model1.index(directory))
        # self.pushButton_start.setEnabled(True)

    def match_found(self, result):
        # print("MATCH FOUND + " + str(result))
        file_name = result.split(D)[0]
        file_ext = result.split(D)[1]
        file_size = result.split(D)[2]
        c_time = result.split(D)[3]
        m_time = result.split(D)[4]
        a_time = result.split(D)[5]
        file_ver = result.split(D)[6]
        file_path = result.split(D)[7]
        file_md5 = result.split(D)[8]
        file_sha1 = result.split(D)[9]
        type = result.split(D)[10]
        rowPosition = self.tableWidget_2.rowCount()
        self.tableWidget_2.insertRow(rowPosition)
        self.tableWidget_2.setItem(rowPosition, 0, QTableWidgetItem(type))
        self.tableWidget_2.setItem(rowPosition, 1, QTableWidgetItem(file_name))
        self.tableWidget_2.setItem(rowPosition, 2, QTableWidgetItem(file_ext))
        self.tableWidget_2.setItem(rowPosition, 3, QTableWidgetItem(file_size))
        self.tableWidget_2.setItem(rowPosition, 4, QTableWidgetItem(str(c_time)))
        self.tableWidget_2.setItem(rowPosition, 5, QTableWidgetItem(str(m_time)))
        self.tableWidget_2.setItem(rowPosition, 6, QTableWidgetItem(str(a_time)))
        self.tableWidget_2.setItem(rowPosition, 7, QTableWidgetItem(file_ver))
        self.tableWidget_2.setItem(rowPosition, 8, QTableWidgetItem(file_path))
        self.tableWidget_2.setItem(rowPosition, 9, QTableWidgetItem(file_md5))
        self.tableWidget_2.setItem(rowPosition, 10, QTableWidgetItem(file_sha1))
        self.tableWidget_2.resizeColumnsToContents()
        self.tableWidget_2.scrollToBottom()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Warning',
                                           "No data currently saves, are you sure you want to exit?", QMessageBox.Yes, QMessageBox.No)
        if reply == QMessageBox.Yes:
            settings_save = {
                "geometry": self.saveGeometry(),
                'splitter': self.splitter.saveState(),
                'splitter_2': self.splitter_2.saveState(),
                'splitter_3': self.splitter_3.saveState(),
            }
            # Write window size and position to config file
            # self.settings.setValue("size", self.size())
            # self.settings.setValue("pos", self.pos())
            for i, j in settings_save.items():
                self.settings.setValue(i, j)
            self.settings.sync()
            try:
                event.accept()
            except AttributeError:
                sys.exit()
        if reply == QMessageBox.No:
            event.ignore()

def main():
    app = QApplication(sys.argv)
    UIWindow = UI()
    app.setWindowIcon(QIcon('icon\\UpFront.png'))
    app.exec_()

if __name__ == '__main__':
    directory_path = os.getcwd()
    print(directory_path)
    main()

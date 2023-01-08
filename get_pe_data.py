#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
from lief import PE
from lief.PE import oid_to_string
import ppdeep
import datetime
import pefile
import sys
import traceback
import argparse
import sqlite3
import hashlib


class exceptions_handler(object):
    func = None
    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions         = exceptions
        self.on_except_callback = on_except_callback
    def __call__(self, *args, **kwargs):
        if self.func is None:
            self.func = args[0]
            return self
        try:
            return self.func(*args, **kwargs)
        except self.exceptions as e:
            if self.on_except_callback is not None:
                self.on_except_callback(e)
            else:
                print("-" * 60)
                print("Exception in {}: {}".format(self.func.__name__, e))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                print("-" * 60)


@exceptions_handler(Exception)
def create_database(db_location, file):
    sha256_hash = ''
    if os.path.isfile(file):
        with open(file, "rb") as in_file:
            sha256 = hashlib.sha256()
            block_size = 2 ** 20
            while True:
                data = in_file.read(block_size)
                if not data:
                    break
                sha256.update(data)
            sha256_hash = sha256.hexdigest()
            print(sha256_hash)
    db_path = db_location + "\\pe_temp\\" + sha256_hash + ".db"
    try:
        sqliteConnection = sqlite3.connect(db_location)
        cursor = sqliteConnection.cursor()
    except sqlite3.Error as error:
        print("Failed to connect with sqlite3 database - " + str(error))


@exceptions_handler(Exception)
def get_information(binary, file, fuzzy):
    info = []
    fuzzy_hash = ppdeep.hash_from_file(file)
    imp_hash = PE.get_imphash(binary)
    format_str = "{:<30} {:<36}"
    format_hex = "{:<30} 0x{:<34x}"
    info.append("=== Information ===")
    info.append(format_str.format("Name:",                       binary.name))
    info.append(format_hex.format("Virtual size:",               binary.virtual_size))
    info.append(format_str.format("Imphash:",                    str(imp_hash)))
    info.append(format_str.format("PIE:",                        str(binary.is_pie)))
    info.append(format_str.format("NX (Non-Executable Stack):",  str(binary.has_nx)))
    if fuzzy == "YES":
        info.append(format_str.format("SSDeep (Fuzzy):",             fuzzy_hash))
    else:
        pass
    return info

@exceptions_handler(Exception)
def get_header(binary):
    header_list = []
    dos_header       = binary.dos_header
    header           = binary.header
    optional_header  = binary.optional_header
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"
    header_list.append("== Dos Header ==")
    header_list.append(format_str.format("Magic:",                       hex(dos_header.magic)))
    header_list.append(format_dec.format("Used bytes in the last page:", dos_header.used_bytes_in_the_last_page))
    header_list.append(format_dec.format("File size in pages:",          dos_header.file_size_in_pages))
    header_list.append(format_dec.format("Number of relocations:",       dos_header.numberof_relocation))
    header_list.append(format_dec.format("Header size in paragraphs:",   dos_header.header_size_in_paragraphs))
    header_list.append(format_dec.format("Minimum extra paragraphs:",    dos_header.minimum_extra_paragraphs))
    header_list.append(format_dec.format("Maximum extra paragraphs",     dos_header.maximum_extra_paragraphs))
    header_list.append(format_dec.format("Initial relative SS",          dos_header.initial_relative_ss))
    header_list.append(format_hex.format("Initial SP:",                  dos_header.initial_sp))
    header_list.append(format_hex.format("Checksum:",                    dos_header.checksum))
    header_list.append(format_dec.format("Initial IP:",                  dos_header.initial_ip))
    header_list.append(format_dec.format("Initial CS:",                  dos_header.initial_relative_cs))
    header_list.append(format_hex.format("Address of relocation table:", dos_header.addressof_relocation_table))
    header_list.append(format_dec.format("Overlay number:",              dos_header.overlay_number))
    header_list.append(format_dec.format("OEM ID:",                      dos_header.oem_id))
    header_list.append(format_dec.format("OEM information",              dos_header.oem_info))
    header_list.append(format_hex.format("Address of optional header:",  dos_header.addressof_new_exeheader))
    header_list.append("")
    header_list.append("== Header ==")
    char_str = " - ".join([str(chara).split(".")[-1] for chara in header.characteristics_list])
    header_list.append(format_str.format("Signature:",               "".join(map(chr, header.signature))))
    header_list.append(format_str.format("Machine:",                 str(header.machine)))
    header_list.append(format_dec.format("Number of sections:",      header.numberof_sections))
    dtimestamp = header.time_date_stamps
    unixdt = datetime.datetime.fromtimestamp(dtimestamp)
    header_list.append(format_str.format("Time Date stamp:",         str(unixdt) + " UTC  (" + str(dtimestamp) + ")"))
    header_list.append(format_dec.format("Pointer to symbols:",      header.pointerto_symbol_table))
    header_list.append(format_dec.format("Number of symbols:",       header.numberof_symbols))
    header_list.append(format_dec.format("Size of optional header:", header.sizeof_optional_header))
    header_list.append(format_str.format("Characteristics:",         char_str))
    header_list.append("")
    dll_char_str = " - ".join([str(chara).split(".")[-1] for chara in optional_header.dll_characteristics_lists])
    subsystem_str = str(optional_header.subsystem).split(".")[-1]
    header_list.append("== Optional Header ==")
    magic = "PE32" if optional_header.magic == PE.PE_TYPE.PE32 else "PE64"
    header_list.append(format_str.format("Magic:", magic))
    header_list.append(format_dec.format("Major linker version:",           optional_header.major_linker_version))
    header_list.append(format_dec.format("Minor linker version:",           optional_header.minor_linker_version))
    header_list.append(format_str.format("Size of code:",                   str(optional_header.sizeof_code) + "  bytes"))
    header_list.append(format_str.format("Size of initialized data:",       str(optional_header.sizeof_initialized_data)  + "  bytes"))
    header_list.append(format_str.format("Size of uninitialized data:",     str(optional_header.sizeof_uninitialized_data)  + "  bytes"))
    header_list.append(format_hex.format("Entry point:",                    optional_header.addressof_entrypoint))
    header_list.append(format_hex.format("Base of code:",                   optional_header.baseof_code))
    if magic == "PE32":
        header_list.append(format_hex.format("Base of data",                optional_header.baseof_data))
    header_list.append(format_hex.format("Image base:",                     optional_header.imagebase))
    header_list.append(format_hex.format("Section alignment:",              optional_header.section_alignment))
    header_list.append(format_hex.format("File alignment:",                 optional_header.file_alignment))
    header_list.append(format_dec.format("Major operating system version:", optional_header.major_operating_system_version))
    header_list.append(format_dec.format("Minor operating system version:", optional_header.minor_operating_system_version))
    header_list.append(format_dec.format("Major image version:",            optional_header.major_image_version))
    header_list.append(format_dec.format("Minor image version:",            optional_header.minor_image_version))
    header_list.append(format_dec.format("Major subsystem version:",        optional_header.major_subsystem_version))
    header_list.append(format_dec.format("Minor subsystem version:",        optional_header.minor_subsystem_version))
    header_list.append(format_dec.format("WIN32 version value:",            optional_header.win32_version_value))
    header_list.append(format_str.format("Size of image:",                  str(optional_header.sizeof_image) + "  bytes"))
    header_list.append(format_str.format("Size of headers:",                str(optional_header.sizeof_headers) + "  bytes"))
    header_list.append(format_hex.format("Checksum:",                       optional_header.checksum))
    header_list.append(format_str.format("Subsystem:",                      subsystem_str))
    header_list.append(format_str.format("DLL Characteristics:",            dll_char_str))
    header_list.append(format_hex.format("Size of stack reserve:",          optional_header.sizeof_stack_reserve))
    header_list.append(format_hex.format("Size of stack commit:",           optional_header.sizeof_stack_commit))
    header_list.append(format_hex.format("Size of heap reserve:",           optional_header.sizeof_heap_reserve))
    header_list.append(format_hex.format("Size of heap commit:",            optional_header.sizeof_heap_commit))
    header_list.append(format_dec.format("Loader flags:",                   optional_header.loader_flags))
    header_list.append(format_dec.format("Number of RVA and size:",         optional_header.numberof_rva_and_size))
    return header_list

@exceptions_handler(Exception)
def get_data_directories(binary):
    dir_list = []
    data_directories = binary.data_directories
    dir_list.append("== Data Directories ==")
    f_title = "|{:<24} | {:<10} | {:<10} | {:<8} |"
    f_value = "|{:<24} | 0x{:<8x} | 0x{:<8x} | {:<8} |"
    dir_list.append(f_title.format("Type", "RVA", "Size", "Section"))
    for directory in data_directories:
        section_name = directory.section.name if directory.has_section else ""
        dir_list.append(f_value.format(str(directory.type).split('.')[-1], directory.rva, directory.size, section_name))
    return dir_list

@exceptions_handler(Exception)
def get_sections(binary):
    section_list = []
    sections = binary.sections
    section_list.append("== Sections  ==")
    f_title = "|{:<10} | {:<16} | {:<16} | {:<18} | {:<16} | {:<9} | {:<9}"
    f_value = "|{:<10} | 0x{:<14x} | 0x{:<14x} | 0x{:<16x} | 0x{:<14x} | {:<9.2f} | {:<9}"
    section_list.append(f_title.format("Name", "Offset", "Size", "Virtual Address", "Virtual size", "Entropy", "Flags"))
    for section in sections:
        flags = ""
        for flag in section.characteristics_lists:
            flags += str(flag).split(".")[-1] + " "
        section_list.append(f_value.format(section.name, section.offset, section.size, section.virtual_address, section.virtual_size, section.entropy, flags))
    return section_list

@exceptions_handler(Exception)
def get_symbols(binary):
    sym_list = []
    symbols = binary.symbols
    if len(symbols) > 0:
        sym_list.append("== Symbols ==")
        f_title = "|{:<20} | {:<10} | {:<8} | {:<8} | {:<8} | {:<13} |"
        f_value = u"|{:<20} | 0x{:<8x} | {:<14} | {:<10} | {:<12} | {:<13} |"
        sym_list.append(f_title.format("Name", "Value", "Section number", "Basic type", "Complex type", "Storage class"))
        for symbol in symbols:
            section_nb_str = ""
            if symbol.section_number <= 0:
                section_nb_str = str(PE.SYMBOL_SECTION_NUMBER(symbol.section_number)).split(".")[-1]
            else:
                try:
                    section_nb_str = symbol.section.name
                except Exception:
                    section_nb_str = "section<{:d}>".format(symbol.section_number)
            sym_list.append(f_value.format(
                symbol.name[:20],
                symbol.value,
                section_nb_str,
                str(symbol.base_type).split(".")[-1],
                str(symbol.complex_type).split(".")[-1],
                str(symbol.storage_class).split(".")[-1]))
    else:
        sym_list.append("== Symbols ==")
        sym_list.append("None Found")
    return sym_list

@exceptions_handler(Exception)
def get_imports(binary):   #
    imp_list = []
    imp_list.append("== Imports ==")
    imports = binary.imports
    for import_ in imports:
        # if resolve:
        #     import_ = lief.PE.resolve_ordinals(import_)
        imp_list.append(import_.name)
        entries = import_.entries
        f_value = "  {:<33} 0x{:<14x} 0x{:<14x} 0x{:<16x}"
        for entry in entries:
            imp_list.append(f_value.format(entry.name, entry.data, entry.iat_value, entry.hint))
    if imp_list == []:
        imp_list.append("None Found")
    return imp_list

@exceptions_handler(Exception)
def get_tls(binary):
    tls_list = []
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    tls_list.append("== TLS ==")
    tls = binary.tls
    callbacks = tls.callbacks
    if len(callbacks) > 0:
        tls_list.append(format_hex.format("Address of callbacks:", tls.addressof_callbacks))
        tls_list.append("Callbacks:")
        for callback in callbacks:
            tls_list.append("  " + hex(callback))
        tls_list.append(format_hex.format("Address of index:", tls.addressof_index))
        tls_list.append(format_hex.format("Size of zero fill:", tls.sizeof_zero_fill))
        tls_list.append("{:<33} 0x{:<10x} 0x{:<10x}".format("Address of raw data:",
                                                            tls.addressof_raw_data[0], tls.addressof_raw_data[1]))
        tls_list.append(format_hex.format("Size of raw data:", len(tls.data_template)))
        tls_list.append(format_hex.format("Characteristics:", tls.characteristics))
        tls_list.append(format_str.format("Section:", tls.section.name))
        tls_list.append(format_str.format("Data directory:", str(tls.directory.type)))
    else:
        tls_list.append("None Found")
    return tls_list

@exceptions_handler(Exception)
def get_relocations(binary):
    reloc_list = []
    relocations = binary.relocations
    reloc_list.append("== Relocations ==")
    for relocation in relocations:
        entries = relocation.entries
        reloc_list.append(hex(relocation.virtual_address))
        for entry in entries:
            reloc_list.append("  0x{:<8x} {:<8}".format(entry.position, str(entry.type).split(".")[-1]))
    return reloc_list

@exceptions_handler(Exception)
def get_export(binary):
    exp_list = []
    exp_list.append("== Exports ==")
    exports = binary.get_export()
    entries = exports.entries
    f_value = "{:<20} 0x{:<10x} 0x{:<10x} 0x{:<6x} 0x{:<6x} 0x{:<10x}"
    exp_list.append(f_value.format(exports.name, exports.export_flags, exports.timestamp, exports.major_version, exports.minor_version, exports.ordinal_base))
    entries = sorted(entries, key=lambda e : e.ordinal)
    for entry in entries:
        extern = "[EXTERN]" if entry.is_extern else ""
        exp_list.append("  {:<20} {:d} 0x{:<10x} {:<13}".format(entry.name[:20], entry.ordinal, entry.address, extern))
    return exp_list

@exceptions_handler(Exception)
def get_debug(binary):
    bug_list = []
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"
    debugs = binary.debug
    bug_list.append("Debug Count ({})".format(len(debugs)))
    for debug in debugs:
        bug_list.append(format_hex.format("Characteristics:",     debug.characteristics))
        dtimestamp = int(debug.timestamp)
        unixdt = datetime.datetime.fromtimestamp(dtimestamp)
        bug_list.append(format_str.format("Timestamp:",           str(dtimestamp) + " (" + str(unixdt) + ")"))
        bug_list.append(format_dec.format("Major version:",       debug.major_version))
        bug_list.append(format_dec.format("Minor version:",       debug.minor_version))
        bug_list.append(format_str.format("Type:",                str(debug.type).split(".")[-1]))
        bug_list.append(format_hex.format("Size of data:",        debug.sizeof_data))
        bug_list.append(format_hex.format("Address of raw data:", debug.addressof_rawdata))
        bug_list.append(format_hex.format("Pointer to raw data:", debug.pointerto_rawdata))
        if debug.has_code_view:
            code_view = debug.code_view
            cv_signature = code_view.cv_signature
            if cv_signature in (lief.PE.CODE_VIEW_SIGNATURES.PDB_70, lief.PE.CODE_VIEW_SIGNATURES.PDB_70):
                sig_str = " ".join(map(lambda e : "{:02x}".format(e), code_view.signature))
                bug_list.append(format_str.format("Code View Signature:", str(cv_signature).split(".")[-1]))
                bug_list.append(format_str.format("Signature:", sig_str))
                bug_list.append(format_dec.format("Age:", code_view.age))
                bug_list.append(format_str.format("Filename:", code_view.filename))
        if debug.has_pogo:
            pogo = debug.pogo
            sig_str = str(pogo.signature).split(".")[-1]
            bug_list.append(format_str.format("Signature:", sig_str))
            bug_list.append("Entries:")
            for entry in pogo.entries:
                bug_list.append("    {:<20} 0x{:x} ({:d})".format(entry.name, entry.start_rva, entry.size))
    return bug_list

@exceptions_handler(Exception)
def get_signature(binary, file):
    cert_list = []
    certs = binary.verify_signature()
    if certs == lief.PE.Signature.VERIFICATION_FLAGS.OK:
        cert_list.append("Signature Validated - " + str(certs) + "\n")
    else:
        cert_list.append("Signature Not Valid - " + str(certs) + "\n")
    format_str = "{:<33} {:<30}"
    format_dec = "{:<33} {:<30d}"
    for signature in binary.signatures:
        cert_list.append(signature)
    return cert_list

@exceptions_handler(Exception)
def get_rich_header(binary, file_path):
    binary2 = pefile.PE(file_path)
    rich_list = []
    check_list = []
    rich_list.append("== Rich Header ==")
    header = binary.rich_header
    rich_list.append("Key          : " + hex(header.key))
    rich_list.append("Rich Hash    : " + str(binary2.get_rich_header_hash()))
    for entry in header.entries:
        with open("lookups//comp_id.txt", "r") as file:
            for line in file:
                if (f'{entry.id:04x}' + f'{entry.build_id:04x}') in line:
                    name = "   [" + line.split("[")[1].strip()
                    rich_list.append(
                        "  - ID: {:04x} Build ID: {:04x} Count: {:}".format(entry.id, entry.build_id, str(entry.count) + name))
                    check_list.append(f'{entry.id:04x}' + f'{entry.build_id:04x}')
                else:
                    pass
        if (f'{entry.id:04x}' + f'{entry.build_id:04x}') in check_list:
            pass
        else:
            rich_list.append("  - ID: {:04x} Build ID: {:04x} Count: {:}".format(entry.id, entry.build_id, str(entry.count)))
            check_list.append(f'{entry.id:04x}' + f'{entry.build_id:04x}')
    return rich_list

@exceptions_handler(Exception)
def get_resources(binary):
    rec_list = []
    rec_list.append("== Resources ==")
    try:
        manager = binary.resources_manager
        rec_list.append(manager)
    except Exception as ee:
        print(str(ee))
    return rec_list

@exceptions_handler(Exception)
def get_load_configuration(binary):
    load_list = []
    format_str = "{:<45} {:<30}"
    format_hex = "{:<45} 0x{:<28x}"
    format_dec = "{:<45} {:<30d}"
    load_list.append("== Load Configuration ==")
    try:
        config = binary.load_configuration
        load_list.append(format_str.format("Version:",                          str(config.version).split(".")[-1]))
        load_list.append(format_dec.format("Characteristics:",                  config.characteristics))
        load_list.append(format_dec.format("Timedatestamp:",                    config.timedatestamp))
        load_list.append(format_dec.format("Major version:",                    config.major_version))
        load_list.append(format_dec.format("Minor version:",                    config.minor_version))
        load_list.append(format_hex.format("Global flags clear:",               config.global_flags_clear))
        load_list.append(format_hex.format("Global flags set:",                 config.global_flags_set))
        load_list.append(format_dec.format("Critical section default timeout:", config.critical_section_default_timeout))
        load_list.append(format_hex.format("Decommit free block threshold:",    config.decommit_free_block_threshold))
        load_list.append(format_hex.format("Decommit total free threshold:",    config.decommit_total_free_threshold))
        load_list.append(format_hex.format("Lock prefix table:",                config.lock_prefix_table))
        load_list.append(format_hex.format("Maximum allocation size:",          config.maximum_allocation_size))
        load_list.append(format_hex.format("Virtual memory threshold:",         config.virtual_memory_threshold))
        load_list.append(format_hex.format("Process affinity mask:",            config.process_affinity_mask))
        load_list.append(format_hex.format("Process heap flags:",               config.process_heap_flags))
        load_list.append(format_hex.format("CSD Version:",                      config.csd_version))
        load_list.append(format_hex.format("Reserved 1:",                       config.reserved1))
        load_list.append(format_hex.format("Edit list:",                        config.editlist))
        load_list.append(format_hex.format("Security cookie:",                  config.security_cookie))
        if isinstance(config, lief.PE.LoadConfigurationV0):
            load_list.append(format_hex.format("SE handler table:", config.se_handler_table))
            load_list.append(format_dec.format("SE handler count:", config.se_handler_count))
        if isinstance(config, lief.PE.LoadConfigurationV1):
            flags_str = " - ".join(map(lambda e : str(e).split(".")[-1], config.guard_cf_flags_list))
            load_list.append(format_hex.format("GCF check function pointer:",    config.guard_cf_check_function_pointer))
            load_list.append(format_hex.format("GCF dispatch function pointer:", config.guard_cf_dispatch_function_pointer))
            load_list.append(format_hex.format("GCF function table :",           config.guard_cf_function_table))
            load_list.append(format_dec.format("GCF Function count :",           config.guard_cf_function_count))
            load_list.append("{:<45} {} (0x{:x})".format("Guard flags:", flags_str, int(config.guard_flags)))
        if isinstance(config, lief.PE.LoadConfigurationV2):
            code_integrity = config.code_integrity
            load_list.append("Code Integrity:")
            load_list.append(format_dec.format(" " * 3 + "Flags:",          code_integrity.flags))
            load_list.append(format_dec.format(" " * 3 + "Catalog:",        code_integrity.catalog))
            load_list.append(format_hex.format(" " * 3 + "Catalog offset:", code_integrity.catalog_offset))
            load_list.append(format_dec.format(" " * 3 + "Reserved:",       code_integrity.reserved))
        if isinstance(config, lief.PE.LoadConfigurationV3):
            load_list.append(format_hex.format("Guard address taken iat entry table:", config.guard_address_taken_iat_entry_table))
            load_list.append(format_hex.format("Guard address taken iat entry count:", config.guard_address_taken_iat_entry_count))
            load_list.append(format_hex.format("Guard long jump target table:",        config.guard_long_jump_target_table))
            load_list.append(format_hex.format("Guard long jump target count:",        config.guard_long_jump_target_count))
        if isinstance(config, lief.PE.LoadConfigurationV4):
            load_list.append(format_hex.format("Dynamic value relocation table:", config.dynamic_value_reloc_table))
            load_list.append(format_hex.format("Hybrid metadata pointer:",        config.hybrid_metadata_pointer))
        if isinstance(config, lief.PE.LoadConfigurationV5):
            load_list.append(format_hex.format("GRF failure routine:",                  config.guard_rf_failure_routine))
            load_list.append(format_hex.format("GRF failure routine function pointer:", config.guard_rf_failure_routine_function_pointer))
            load_list.append(format_hex.format("Dynamic value reloctable offset:",      config.dynamic_value_reloctable_offset))
            load_list.append(format_hex.format("Dynamic value reloctable section:",     config.dynamic_value_reloctable_section))
        if isinstance(config, lief.PE.LoadConfigurationV6):
            load_list.append(format_hex.format("GRF verify stackpointer function pointer:", config.guard_rf_verify_stackpointer_function_pointer))
            load_list.append(format_hex.format("Hotpatch table offset:",                    config.hotpatch_table_offset))
        if isinstance(config, lief.PE.LoadConfigurationV7):
            load_list.append(format_hex.format("Reserved 3:", config.reserved3))
        if load_list == []:
            load_list.append("None Found")
    except ValueError as ve:
        load_list.append("None Found : " + str(ve))
        pass
    except TypeError as te:
        load_list.append("None Found : " + str(te))
        pass
    except:
        load_list.append("None Found : Other Errors Occured")
        pass
    return load_list

@exceptions_handler(Exception)
def get_ctor(binary):
    cons_list = []
    cons_list.append("== Constructors ==\n")
    cons_list.append("Functions: ({:d})".format(len(binary.ctor_functions)))
    for idx, f in enumerate(binary.ctor_functions):
        cons_list.append("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))
    return cons_list

@exceptions_handler(Exception)
def get_exception_functions(binary):
    exc_list = []
    exc_list.append("== Exception functions ==\n")
    exc_list.append("Functions: ({:d})".format(len(binary.exception_functions)))
    for idx, f in enumerate(binary.exception_functions):
        exc_list.append("    [{:d}] {}: 0x{:x}".format(idx, f.name, f.address))
    return exc_list

@exceptions_handler(Exception)
def get_functions(binary):
    func_list = []
    func_list.append("== Functions ==\n")
    func_list.append("Functions: ({:d})".format(len(binary.functions)))
    for idx, f in enumerate(binary.functions):
        func_list.append("    [{:d}] {}: 0x{:x} ({:d} bytes)".format(idx, f.name, f.address, f.size))
    return func_list

@exceptions_handler(Exception)
def get_delay_imports(binary):
    delay_list = []
    delay_imports = binary.delay_imports
    if len(delay_imports) == 0:
        delay_list.append("== Delay Imports ==\n")
        delay_list.append("None Found")
        return delay_list
    delay_list.append("== Delay Imports ==\n")
    for imp in delay_imports:
        delay_list.append(imp.name)
        delay_list.append("  Attribute:   {}".format(imp.attribute))
        delay_list.append("  Handle:      0x{:x}".format(imp.handle))
        delay_list.append("  IAT:         0x{:x}".format(imp.iat))
        delay_list.append("  Names Table: 0x{:x}".format(imp.names_table))
        delay_list.append("  Bound IAT:   0x{:x}".format(imp.biat))
        delay_list.append("  Unload IAT:  0x{:x}".format(imp.uiat))
        delay_list.append("  Timestamp:   0x{:x}".format(imp.timestamp))
        for entry in imp.entries:
            delay_list.append("    {:<25} 0x{:08x}: 0x{:010x} - 0x{:x}".format(entry.name, entry.value, entry.iat_value, entry.hint))
    return delay_list

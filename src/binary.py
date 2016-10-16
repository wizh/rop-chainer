from __future__ import with_statement
from ctypes import *
from sys import exit

class Flags:
    ELFCLASS32    = 0x01
    ELFDATALSB    = 0x01
    EM_X86        = 0x03
    PF_X          = 0x1
    SF_ALLOC      = 0x2
    SF_EXECINSTR  = 0x4

class Offsets:
    EI_MAGIC    = 0x00
    EI_CLASS    = 0x04
    EI_DATA     = 0x05
    EMachine    = 0x12

class FileHeader(LittleEndianStructure):
    _fields_ = [("e_ident",         c_ubyte * 16),
                ("e_type",          c_ushort),
                ("e_machine",       c_ushort),
                ("e_version",       c_uint),
                ("e_entry",         c_uint),
                ("e_phoff",         c_uint),
                ("e_shoff",         c_uint),
                ("e_flags",         c_uint),
                ("e_ehsize",        c_ushort),
                ("e_phentsize",     c_ushort),
                ("e_phnum",         c_ushort),
                ("e_shentsize",     c_ushort),
                ("e_shnum",         c_ushort),
                ("e_shstrndx",      c_ushort)]

class ProgramHeader(LittleEndianStructure):
    _fields_ = [("p_type",       c_uint),
                ("p_offset",     c_uint),
                ("p_vaddr",      c_uint),
                ("p_paddr",      c_uint),
                ("p_filesz",     c_uint),
                ("p_memsz",      c_uint),
                ("p_flags",      c_uint),
                ("p_align",      c_uint)]

class SectionHeader(LittleEndianStructure):
    _fields_ = [("sh_name",         c_uint),
                ("sh_type",         c_uint),
                ("sh_flags",        c_uint),
                ("sh_addr",         c_uint),
                ("sh_offset",       c_uint),
                ("sh_size",         c_uint),
                ("sh_link",         c_uint),
                ("sh_info",         c_uint),
                ("sh_addralign",    c_uint)]

class Binary:
    def __init__(self, options):
        self.__binary = None
        self.__file_header = None
        self.__section_headers = []
        self.__program_headers = []

        self.__parseBinary(options)

        self.__parseFileHeader()

        self.checkArch()

        self.__parseSectionsHeaders()
        self.__parseProgramHeaders()

    def __parseBinary(self, options):
        try:
            with open(options.binary, "rb") as f:
                self.__binary = bytearray(f.read())
        except EnvironmentError:
            print("Can't read binary")
            exit()

    def __parseFileHeader(self):
        self.__file_header = FileHeader.from_buffer_copy(self.__binary)

    def __parseSectionsHeaders(self):
        base = self.__binary[self.__file_header.e_shoff:]
        for i in range(self.__file_header.e_shnum):
            header = SectionHeader.from_buffer_copy(base)

            self.__section_headers.append(header)
            base = base[self.__file_header.e_shentsize:]

    def __parseProgramHeaders(self):
        base = self.__binary[self.__file_header.e_phoff:]
        for i in range(self.__file_header.e_phnum):
            header = ProgramHeader.from_buffer_copy(base)
            self.__program_headers.append(header)

            base = base[self.__file_header.e_phentsize:]

    def getDataSectionOffset(self):
        name_indexes = str(self.__binary[(self.__section_headers[self.__file_header.e_shstrndx].sh_offset):])
        for i in range(self.__file_header.e_shnum):
            if (name_indexes[self.__section_headers[i].sh_name:]).split('\0')[0] == ".data":
                return self.__section_headers[i].sh_addr
        return None

    def getDataSections(self):
        data_sections = []
        for section in self.__section_headers:
            if not ((section.sh_flags & Flags.SHF_ALLOC) and
                    (section.sh_flags & Flags.SHF_EXECINSTR)):
                data_sections += \
                    [{"offset" : section.sh_offset,
                      "size"   : section.sh_size,
                      "vaddr"  : section.sh_addr,
                      "data"   : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])}]
        return data_sections

    def getExecSections(self):
        exec_sections = []
        for segment in self.__program_headers:
            if segment.p_flags & Flags.PF_X:
                exec_sections += \
                    [{"offset" : segment.p_offset,
                      "size"   : segment.p_memsz,
                      "vaddr"  : segment.p_vaddr,
                      "data"   : str(self.__binary[segment.p_offset:segment.p_offset + segment.p_memsz])}]
        return exec_sections

    def checkArch(self):
        # Check architecture
        if self.__file_header.e_machine != Flags.EM_X86:
            print("Architecture target not supported")
            exit()
        # Check 32/64 bit
        if self.__file_header.e_ident[Offsets.EI_CLASS] != Flags.ELFCLASS32:
            print("Architecture mode not supported")
            exit()
        # Check little/big endian
        if self.__file_header.e_ident[Offsets.EI_DATA] != Flags.ELFDATALSB:
            print("Architecture endian not supported")
            exit()
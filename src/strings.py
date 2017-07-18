import re

class Strings:
    def __init__(self, sections):
        self.__useful = ["/bin/sh", "/bin/bash", "bin", "bash", "sh", "/"]
        self.__strings = []

        self.__locateUseful(sections)
        self.__deleteDuplicateStrings()

    def __deleteDuplicateStrings(self):
        unique_strings = []
        unique_texts = []
        for string in self.__strings:
            if string["text"] in unique_texts:
                continue
            unique_strings.append(string)
            unique_texts.append(string["text"])
        self.__strings = unique_strings

    def __locateUseful(self, sections):
        for section in sections:
            for string in self.__useful:
                matches = [m.start() for m in re.finditer(string, section["data"])]
                for index in matches:
                    self.__strings +=\
                        [{"text" : section["data"][index:index+len(string)],
                          "vaddr"  : section["vaddr"] + index}]

    def prettyPrintStrings(self):
        print 'Strings:'
        for string in self.__strings:
            print '0x%x: %s' % (string["vaddr"], string["text"])

        print '------------------------------------------------------'

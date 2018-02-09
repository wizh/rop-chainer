from argparse import ArgumentParser

class Arguments(object):
    def __init__(self):
        parser = ArgumentParser(description=("List gadgets found in x86 ELF binaries."))
        parser.add_argument("binary",
                            type=str, metavar="<binary>", help="filename of binary")
        parser.add_argument("--depth",
                            type=int, metavar="<depth>", default=5,
                            help="depth of search for gadgets")
        parser.add_argument("--chain",
                            dest='chain', default=False, action='store_true',
                            help="enable chain generation")

        self._args = parser.parse_args()

    def get_args(self):
        return self._args

import re

class Node:
    symbol_counts = {}
    RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

    def __init__(self, symbol=None):
        self.symbol = symbol
        if symbol in Node.symbol_counts:
            Node.symbol_counts[symbol] += 1
        else:
            Node.symbol_counts[symbol] = 1

        self.id = "{}:{}>".format(symbol[:-1], Node.symbol_counts[symbol])
        self.children = []
        self.is_terminal = not re.match(self.RE_NONTERMINAL, symbol)

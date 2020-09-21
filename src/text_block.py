class TextBlock(object):
    def __init__(self, header):
        self.header = header
        self.lines = []
        self.blocks = []
        self.footer = []

    def __str__(self):
        ret = self.header
        ret += "\n" + "\n".join(self.lines)
        ret += "\n" + "\n".join([str(block) for block in self.blocks])
        ret += "\n" + "\n".join(self.footer)
        return ret

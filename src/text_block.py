import pdb

class TextBlock(object):
    def __init__(self, header):
        self.header = header
        self.lines = []
        self.blocks = []
        self.footer = []

    def __str__(self):
        str_ret = self.header
        str_ret += "\n{}\n".format("_"*len(self.header))
        str_ret += "\n".join(self.lines)

        if self.blocks:
            str_ret += "\n{}\n".format("=" * len(self.header))
            str_ret += "\n".join([str(block) for block in self.blocks])
            str_ret += "\n{}\n".format("=" * len(self.header))

        str_ret += "\n".join(self.footer)
        return str_ret

    def format(self, prefix="    ", prefix_counter=0):
        tb_prefix = prefix * prefix_counter

        str_ret = tb_prefix + self.header
        str_ret += "\n{}{}\n".format(tb_prefix, "-" * len(self.header))

        if self.lines:
            str_ret += tb_prefix + ("\n"+tb_prefix).join(self.lines)
            len_last_line = (len(str_ret) - str_ret.rfind("\n")) - len(tb_prefix)
            str_ret += "\n{}{}".format(tb_prefix, "-" * len_last_line)

        if self.blocks:
            for block in self.blocks:
                str_block = block.format(prefix=prefix, prefix_counter=prefix_counter + 1)
                str_ret += str_block

        if self.footer:
            str_ret += tb_prefix + ("\n"+tb_prefix).join(self.footer)
            str_ret += tb_prefix + "-" * len(self.footer[-1])

        if str_ret:
            len_last_line = (len(str_ret) - str_ret.rfind("\n")) - len(tb_prefix)
            str_ret += "\n{}{}\n\n".format(tb_prefix, "=" * len_last_line)

        return str_ret

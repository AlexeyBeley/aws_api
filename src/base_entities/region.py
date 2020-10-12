
class Region:
    def __init__(self):
        self._region_mark = None
        self._region_name = None
        self.connection_steps = []

    @property
    def region_mark(self):
        return self._region_mark

    @region_mark.setter
    def region_mark(self, value):
        self._region_mark = value

    @property
    def region_name(self):
        return self._region_name

    @region_name.setter
    def region_name(self, value):
        self._region_name = value

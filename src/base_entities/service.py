class Service(object):
    ANY = None

    @classmethod
    def any(cls):
        if Service.ANY is None:
            Service.ANY = Service()
        return Service.ANY

    def __init__(self):
        pass

    def __str__(self):
        if self is Service.any():
            return "any"
        raise NotImplementedError

    def copy(self):
        if self is self.any():
            return self.any()

        raise NotImplementedError

    def intersect(self, other):
        if not isinstance(other, Service):
            raise ValueError
        pdb.set_trace()


class ServiceTCP(Service):
    def __init__(self):
        super(ServiceTCP, self).__init__()
        self.start = None
        self.end = None

    def __str__(self):
        return "TCP:[{}-{}]".format(self.start, self.end)

    def copy(self):
        service = Service()
        service.start = self.start
        service.end = self.end
        return service


class ServiceUDP(Service):
    def __init__(self):
        super(ServiceUDP, self).__init__()
        self.start = None
        self.end = None

    def __str__(self):
        return "UDP:[{}-{}]".format(self.start, self.end)

    def copy(self):
        service = Service()
        service.start = self.start
        service.end = self.end
        return service


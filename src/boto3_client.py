import threading
from boto3.session import Session
import pdb


class Boto3Client(object):
    CLIENTS = {}
    LOCK = threading.Lock()
    SESSION = None
    EXEC_COUNT = 0

    def __init__(self, client_name, aws_key_id, aws_access_secret, region_name, logger):
        """
        self.client shouldn't be inited, the init should be done on demand if execute is called

        :param client_name:
        :param aws_key_id:
        :param aws_access_secret:
        :param region_name:
        :param logger:
        """
        self.aws_key_id = aws_key_id
        self.aws_access_secret = aws_access_secret
        self.region_name = region_name

        self.client_name = client_name
        self.logger = logger
        self.connected = False

    @property
    def client(self):
        ret = None
        if self.client_name in self.CLIENTS:
            ret = self.CLIENTS[self.client_name]
        return ret

    @client.setter
    def client(self, _):
        raise NotImplementedError

    def _connect_client(self):
        acquired = self.LOCK.acquire(blocking=False)
        try:
            if acquired is True:
                if self.client_name not in self.CLIENTS:
                    self.CLIENTS[self.client_name] = self.SESSION.client(self.client_name)

        finally:
            self.LOCK.release()

    def _connect(self):
        self._connect_session()
        self._connect_client()

    def _connect_session(self):
        try:
            self.SESSION = Session(aws_access_key_id=self.aws_key_id,
                                   aws_secret_access_key=self.aws_access_secret,
                                   region_name=self.region_name)
            self.connected = True
        except Exception as inst:
            self.logger.warning("Can't open session to AWS: {}".format(str(inst)))

    def yield_with_paginator(self, command, return_string):
        for _page in self.client.get_paginator(command).paginate():
            for response_obj in _page[return_string]:
                yield response_obj

    def get_with_paginator(self, command, return_string, filters_req=None):
        ret = []
        if filters_req is None:
            filters_req = {}
        for _page in self.client.get_paginator(command).paginate(**filters_req):
            Boto3Client.EXEC_COUNT += 1
            ret += _page[return_string]

        return ret

    def execute(self, command, return_string, filters_req=None, debug=False):
        Boto3Client.EXEC_COUNT += 1
        if filters_req is None:
            filters_req = {}

        if self.client is None:
            self._connect()

        if debug:
            pdb.set_trace()

        if self.client.can_paginate(command):
            return self.get_with_paginator(command, return_string, filters_req=filters_req)

        try:
            func_exec = getattr(self.client, command)
        except AttributeError:
            raise self.UnknownCommandError(command)

        response = func_exec(**filters_req)
        return response[return_string]

    class UnknownCommandError(Exception):
        pass

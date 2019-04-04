import threading
from boto3.session import Session
import pdb


class Boto3Client(object):
    CLIENTS = {}
    LOCK = threading.Lock()
    SESSION = None

    def __init__(self, client_name, aws_key_id, aws_access_secret, region_name, logger):
        # self._connect_session()
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
        self._connect_client()

    def _connect_client(self):
        acquired = self.LOCK.acquire(blocking=False)
        try:
            if acquired is True:
                if self.client_name not in self.CLIENTS:
                    self.CLIENTS[self.client_name] = self.SESSION.client(self.client_name)

        finally:
            self.LOCK.release()

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
            ret += _page[return_string]

        return ret

    def execute(self, command, return_string, filters_req=None):
        try:
            can_paginate = self.client.can_paginate(command)
        except AttributeError:
            self._connect_session()
            self._connect_client()
            can_paginate = self.client.can_paginate(command)

        if can_paginate:
            return self.get_with_paginator(command, return_string, filters_req=filters_req)

        try:
            func_exec = getattr(self.client, command)
        except AttributeError:
            raise self.UnknownCommandError(command)

        response = func_exec(**filters_req)
        return response[return_string]

    class UnknownCommandError(Exception):
        pass

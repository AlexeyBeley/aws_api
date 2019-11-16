import threading
from boto3.session import Session
import pdb


class Boto3Client1(object):
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

    # Shamelessly stolen from: https://medium.com/@vadimpushtaev/decorator-inside-python-class-1e74d23107f6
    class Decorators(object):
        def requires_connection(fn):
            def wrapper(*args, **kwargs):
                self = args[0]
                if self.client is None:
                    self._connect()

                return fn(*args, **kwargs)

            return wrapper

    @Decorators.requires_connection
    def yield_with_paginator(self, command, return_string):
        for _page in self.client.get_paginator(command).paginate():
            for response_obj in _page[return_string]:
                yield response_obj

    @Decorators.requires_connection
    def get_with_paginator(self, func_command, return_string, filters_req=None):
        ret = []
        if filters_req is None:
            filters_req = {}
        for _page in self.client.get_paginator(func_command.__name__).paginate(**filters_req):
            Boto3Client.EXEC_COUNT += 1
            print(Boto3Client.EXEC_COUNT)
            ret += _page[return_string]

        return ret

    @Decorators.requires_connection
    def execute(self, func_command, return_string, filters_req=None, debug=False):
        Boto3Client.EXEC_COUNT += 1
        print(Boto3Client.EXEC_COUNT)
        if filters_req is None:
            filters_req = {}

        if self.client is None:
            self._connect()

        if debug:
            pdb.set_trace()
        if self.client.can_paginate(func_command.__name__):
            return self.get_with_paginator(func_command, return_string, filters_req=filters_req)

        response = func_command(**filters_req)
        return response[return_string]

class DecoratorDescriptor(object):
    def __get__(self, instance, owner):
        """
        Used to return the descriptor when decorates child-classes' methods

        :param instance:
        :param owner:
        :return:
        """
        return self

    def __set__(self, instance, value):
        raise AttributeError("Descriptor Is not settable")

    def __call__(self, func_base):
        """
        Used, when accessed to the descriptor in order to decorate a method
        :param func_base:
        :return:
        """
        def wrapper(*args, **kwargs):
            instance = args[0]
            if instance.client is None:
                instance.connect()

            return func_base(*args, **kwargs)

        return wrapper


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

    requires_connection = DecoratorDescriptor()

    def _connect_client(self):
        acquired = self.LOCK.acquire(blocking=False)
        try:
            if acquired is True:
                if self.client_name not in self.CLIENTS:
                    self.CLIENTS[self.client_name] = self.SESSION.client(self.client_name)

        finally:
            self.LOCK.release()

    def connect(self):
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

    def yield_with_paginator(self, func_command, return_string, filters_req=None):
        """
        Function to yeild replies, if there is no need to get all replies.
        It can save API requests if the expected information found before.

        :param func_command: Bound method from _client instance
        :param return_string: string to retrive the infromation from reply dict
        :param filters_req: filters dict passed to the API client to filter the response
        :return: list of replies
        """
        if filters_req is None:
            filters_req = {}

        for _page in self.client.get_paginator(func_command.__name__).paginate(**filters_req):
            Boto3Client.EXEC_COUNT += 1
            print("Executed API Calls Count:".format(Boto3Client.EXEC_COUNT))
            for response_obj in _page[return_string]:
                yield response_obj

    @requires_connection
    def execute(self, func_command, return_string, filters_req=None):
        """
        Command to execute clients bound function- execute with paginator if available.

        :param func_command: Bound method from _client instance
        :param return_string: string to retrive the infromation from reply dict
        :param filters_req: filters dict passed to the API client to filter the response
        :return: list of replies
        """

        if filters_req is None:
            filters_req = {}

        if self.client.can_paginate(func_command.__name__):
            for ret_obj in self.yield_with_paginator(func_command, return_string, filters_req=filters_req):
                yield ret_obj
            return

        Boto3Client.EXEC_COUNT += 1
        response = func_command(**filters_req)

        if type(response[return_string]) is list:
            ret_lst = response[return_string]
        elif type(response[return_string]) in [str, dict]:
            ret_lst = [response[return_string]]
        else:
            raise NotImplementedError("{} type:{}".format(response[return_string], type(response[return_string])))

        for ret_obj in ret_lst:
            yield ret_obj

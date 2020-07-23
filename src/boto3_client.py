import threading
import boto3
import botocore
from contextlib import contextmanager
import pdb
import datetime
from dateutil.tz import tzlocal


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


class LockAcquiringFailError(Exception):
    pass


class SessionsManager(object):
    LOCK = threading.Lock()
    SESSION_CLIENTS = {}  # {Session: {client_name: client}}
    SESSIONS_STACK = []
    ASSUME_ROLE_SESSION_EXPIRY_WINDOW_SECONDS = 60 * 15

    @staticmethod
    def get_current_session():
        """

        :return: None if no session yet
        """

        if len(SessionsManager.SESSIONS_STACK) != 0:
            return SessionsManager.SESSIONS_STACK[-1]

    @staticmethod
    def connect_session(aws_key_id: str = None, aws_access_secret: str = None, region_name: str = None):
        if SessionsManager.get_current_session() is not None:
            raise RuntimeError("Multiple sessions' stacks not supported")

        try:
            session = boto3.session.Session(aws_access_key_id=aws_key_id,
                                            aws_secret_access_key=aws_access_secret,
                                            region_name=region_name)

            SessionsManager.add_new_session(session)
            return session
        except Exception as inst:
            print("Can't open session to AWS: {}".format(str(inst)))
            raise

    @staticmethod
    def add_new_session(session):
        SessionsManager.SESSION_CLIENTS[session] = {}
        SessionsManager.SESSIONS_STACK.append(session)

    @staticmethod
    def delete_current_session():
        del SessionsManager.SESSION_CLIENTS[SessionsManager.get_current_session()]
        SessionsManager.SESSIONS_STACK.pop(-1)

    @staticmethod
    def connect_client(client_name, region_name):
        acquired = SessionsManager.LOCK.acquire(blocking=False)
        try:
            if acquired is True:
                session = SessionsManager.get_current_session()
                if session is None:
                    raise RuntimeError("No session to base client on")

                if region_name not in SessionsManager.SESSION_CLIENTS[session]:
                    SessionsManager.SESSION_CLIENTS[session][region_name] = {}

                if client_name not in SessionsManager.SESSION_CLIENTS[session][region_name]:
                    SessionsManager.SESSION_CLIENTS[session][region_name][client_name] = session.client(client_name, region_name=region_name)

            else:
                raise LockAcquiringFailError()
        finally:
            SessionsManager.LOCK.release()

    @staticmethod
    def get_assumed_role_session(role_arn: str):
        """
        Automatically refreshes sessions
        Shamelessly stolen from here:
        https://stackoverflow.com/questions/45518122/boto3-sts-assumerole-with-mfa-working-example

        :param role_arn:
        :return: session
        """

        base_session = SessionsManager.get_current_session() or SessionsManager.connect_session()
        fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
            client_creator=base_session._session.create_client,
            source_credentials=base_session.get_credentials(),
            role_arn=role_arn,
            expiry_window_seconds=SessionsManager.ASSUME_ROLE_SESSION_EXPIRY_WINDOW_SECONDS
        )

        creds = botocore.credentials.DeferredRefreshableCredentials(
            method='assume-role',
            refresh_using=fetcher.fetch_credentials,
            time_fetcher=lambda: datetime.datetime.now(tzlocal())
        )
        botocore_session = botocore.session.Session()
        botocore_session._credentials = creds

        return boto3.Session(botocore_session=botocore_session)

    @staticmethod
    def start_assuming_role(role_arn):
        session = SessionsManager.get_assumed_role_session(role_arn)
        SessionsManager.add_new_session(session)

    @staticmethod
    def stop_assuming_role():
        SessionsManager.delete_current_session()

    @staticmethod
    def get_client(client_name, region_name):
        session = SessionsManager.get_current_session()
        if session is None:
            print("session is None")
            return

        if region_name not in SessionsManager.SESSION_CLIENTS[session]:
            print("region is None")
            return

        if client_name not in SessionsManager.SESSION_CLIENTS[session][region_name]:
            print("client name is None")
            return

        return SessionsManager.SESSION_CLIENTS[session][region_name].get(client_name)


class Boto3Client(object):
    EXEC_COUNT = 0
    SESSIONS_MANAGER = SessionsManager()

    def __init__(self, client_name, aws_key_id, aws_access_secret, region_name, logger):
        """
        self.client shouldn't be inited, the init should be done on demand if execute is called
        Client is a singleton identified by client_name and region_name

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
        return self.SESSIONS_MANAGER.get_client(self.client_name, self.region_name)

    @client.setter
    def client(self, _):
        raise RuntimeError("Nobody can set a client explicitly")

    requires_connection = DecoratorDescriptor()

    def connect(self):
        self.SESSIONS_MANAGER.connect_session(aws_key_id=self.aws_key_id, aws_access_secret=self.aws_access_secret, region_name=self.region_name)
        self.SESSIONS_MANAGER.connect_client(self.client_name, self.region_name)

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

    @classmethod
    @requires_connection
    def start_assuming_role(cls, role_arn):
        SessionsManager.start_assuming_role(role_arn)

    @classmethod
    def stop_assuming_role(cls):
        SessionsManager.stop_assuming_role()

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

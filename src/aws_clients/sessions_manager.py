import threading
import boto3
import botocore
import pdb
import sys
import datetime
from dateutil.tz import tzlocal

sys.path.insert(0, "/Users/alexeybe/private/aws_api/src/base_entities")
from environment import Environment

class LockAcquiringFailError(Exception):
    pass


class SessionsManager(object):
    LOCK = threading.Lock()
    CONNECTIONS = {}  # {Session: {client_name: client}}
    ASSUME_ROLE_SESSION_EXPIRY_WINDOW_SECONDS = 60 * 15

    class Connection:
        def __init__(self, session):
            self.session = session
            self.clients = dict()

        def get_client(self, client_name):
            if client_name not in self.clients:
                self.clients[client_name] = SessionsManager.connect_client(connection, client_name)
            return SessionsManager.CONNECTIONS[connection].get(client_name)

    @staticmethod
    def get_connection():
        """

        :return: Connects Session if there is no one already
        """

        environment = Environment.get_environment()
        connection = SessionsManager.CONNECTIONS.get(environment)
        if connection is not None:
            return connection

        session = SessionsManager.connect_session()
        connection = SessionsManager.Connection(session)
        SessionsManager.add_new_connection(environment, connection)

        return connection

    @staticmethod
    def connect_session():
        environment = Environment.get_environment()

        session = boto3.session.Session(aws_access_key_id=environment.connection_steps[0].aws_access_key_id,
                                        aws_secret_access_key=environment.connection_steps[0].aws_secret_access_key,
                                        region_name=environment.connection_steps[0].region.region_mark)

        return session

    @staticmethod
    def add_new_connection(environment, connection):
        SessionsManager.CONNECTIONS[environment] = connection

    @staticmethod
    def delete_current_session():
        del SessionsManager.CONNECTIONS[SessionsManager.get_current_session()]

    @staticmethod
    def connect_client(client_name):
        acquired = SessionsManager.LOCK.acquire(blocking=False)
        try:
            if acquired is True:
                session = SessionsManager.get_current_session()
                if session is None:
                    raise RuntimeError("No session to base client on")

                if region_name not in SessionsManager.CONNECTIONS[session]:
                    SessionsManager.CONNECTIONS[session][region_name] = {}

                if client_name not in SessionsManager.CONNECTIONS[session][region_name]:
                    SessionsManager.CONNECTIONS[session][region_name][client_name] = session.client(client_name, region_name=region_name)

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
        #SessionsManager.add_new_session(session)
        return session

    @staticmethod
    def stop_assuming_role():
        SessionsManager.delete_current_session()

    @staticmethod
    def get_client(client_name):
        """
        Connects if no clients

        :param client_name:
        :return:
        """

        connection = SessionsManager.get_connection()
        return connection.get_client(client_name)



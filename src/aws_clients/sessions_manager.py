import threading
import boto3
import botocore
import pdb
import sys
import datetime
from dateutil.tz import tzlocal
from typing import Any

sys.path.insert(0, "/Users/alexeybe/private/aws_api/src/base_entities")
from environment import Environment


class LockAcquiringFailError(Exception):
    pass


class SessionsManager(object):
    CONNECTIONS = {}  # {Session: {client_name: client}}
    ASSUME_ROLE_SESSION_EXPIRY_WINDOW_SECONDS = 60 * 15

    class Connection:
        LOCK = threading.Lock()

        def __init__(self, session):
            self.session = session
            self.clients = dict()

        def get_client(self, client_name):
            environment = Environment.get_environment()
            region_mark = environment.region.region_mark if environment.region is not None else self.session.region_name

            if region_mark not in self.clients or client_name not in self.clients[region_mark]:
                self.connect_client(region_mark, client_name)

            return self.clients[region_mark][client_name]

        def connect_client(self, region_mark, client_name):
            acquired = SessionsManager.Connection.LOCK.acquire(blocking=False)
            try:
                if acquired is True:
                    if region_mark not in self.clients:
                        self.clients[region_mark] = {}

                    self.clients[region_mark][client_name] = self.session.client(client_name, region_name=region_mark)
                else:
                    raise LockAcquiringFailError()
            finally:
                SessionsManager.Connection.LOCK.release()

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
    def execute_connection_step(connection_step, session):
        if connection_step.type == connection_step.Type.PROFILE:
            if session is not None:
                raise RuntimeError(f"Initial session is not None")

            session = boto3.session.Session(profile_name=connection_step.profile_name,
                                            region_name=connection_step.region.region_mark)
        elif connection_step.type == connection_step.Type.ASSUME_ROLE:
            session = SessionsManager.start_assuming_role(connection_step.role_arn, session)
        else:
            raise NotImplementedError(f"Unknown connection_step type: {connection_step.type}")

        return session

    @staticmethod
    def connect_session():
        environment = Environment.get_environment()
        if len(environment.connection_steps) == 0:
            raise RuntimeError(f"No connection steps defined for environment: '{environment.id}'")

        session = None
        for connection_step in environment.connection_steps:
            session = SessionsManager.execute_connection_step(connection_step, session)

        if session is None:
            raise RuntimeError(f"Could not establish session for environment {environment.id}")


        return session

    @staticmethod
    def add_new_connection(environment, connection):
        SessionsManager.CONNECTIONS[environment] = connection

    @staticmethod
    def delete_current_session():
        del SessionsManager.CONNECTIONS[SessionsManager.get_current_session()]

    @staticmethod
    def start_assuming_role(role_arn: str, session: Any):
        """
        Automatically refreshes sessions
        Shamelessly stolen from here:
        https://stackoverflow.com/questions/45518122/boto3-sts-assumerole-with-mfa-working-example

        :param session:
        :param role_arn:
        :return: session
        """

        fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
            client_creator=session._session.create_client,
            source_credentials=session.get_credentials(),
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



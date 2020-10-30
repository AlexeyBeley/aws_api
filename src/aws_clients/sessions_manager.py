import threading
import boto3
import botocore
import pdb
import sys
import datetime
from dateutil.tz import tzlocal
from typing import Any

sys.path.insert(0, "/Users/alexeybe/private/aws_api/src/base_entities")
from aws_account import AWSAccount


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
            aws_region = AWSAccount.get_aws_region()
            region_mark = aws_region.region_mark if aws_region is not None else self.session.region_name

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
    def get_connection_id():
        aws_account = AWSAccount.get_aws_account()
        aws_region = AWSAccount.get_aws_region()
        region_mark = aws_region.region_mark if aws_region is not None else ""
        return f"{aws_account.id}/{region_mark}"

    @staticmethod
    def get_connection():
        """

        :return: Connects Session if there is no one already
        """

        connection_id = SessionsManager.get_connection_id()
        connection = SessionsManager.CONNECTIONS.get(connection_id)
        if connection is not None:
            return connection

        session = SessionsManager.connect_session()
        connection = SessionsManager.Connection(session)
        SessionsManager.add_new_connection(connection_id, connection)

        return connection

    @staticmethod
    def execute_connection_step(connection_step, session):
        if connection_step.external_id is not None:
            extra_args = {"ExternalId": connection_step.external_id}
        else:
            extra_args = None

        if connection_step.type == connection_step.Type.PROFILE:
            if session is not None:
                raise RuntimeError(f"Initial session is not None")

            session = boto3.session.Session(profile_name=connection_step.profile_name,
                                            region_name=connection_step.region.region_mark)
        elif connection_step.type == connection_step.Type.ASSUME_ROLE:
            session = SessionsManager.start_assuming_role(connection_step.role_arn, session, extra_args=extra_args)
        else:
            raise NotImplementedError(f"Unknown connection_step type: {connection_step.type}")

        return session

    @staticmethod
    def connect_session():
        aws_account = AWSAccount.get_aws_account()
        aws_region = AWSAccount.get_aws_region()

        if aws_region is not None and len(aws_account.regions[aws_region.region_mark].connection_steps) > 0:
            raise NotImplementedError("Per region connection steps not yet implemented")

        if len(aws_account.connection_steps) == 0:
            raise RuntimeError(f"No connection steps defined for aws_account: '{aws_account.id}'")

        session = None
        for connection_step in aws_account.connection_steps:
            session = SessionsManager.execute_connection_step(connection_step, session)

        if session is None:
            raise RuntimeError(f"Could not establish session for aws_account {aws_account.id}")

        return session

    @staticmethod
    def add_new_connection(aws_account, connection):
        SessionsManager.CONNECTIONS[aws_account] = connection

    @staticmethod
    def start_assuming_role(role_arn: str, session: Any, extra_args=None):
        """
        Automatically refreshes sessions
        Shamelessly stolen from here:
        https://stackoverflow.com/questions/45518122/boto3-sts-assumerole-with-mfa-working-example

        :param extra_args: Any additional arguments to add to the assume
            role request using the format of the botocore operation.
            Possible keys include, but may not be limited to,
            DurationSeconds, Policy, SerialNumber, ExternalId and
            RoleSessionName.
        :param session:
        :param role_arn:
        :return: session
        """

        fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
            client_creator=session._session.create_client,
            source_credentials=session.get_credentials(),
            role_arn=role_arn,
            expiry_window_seconds=SessionsManager.ASSUME_ROLE_SESSION_EXPIRY_WINDOW_SECONDS,
            extra_args=extra_args
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



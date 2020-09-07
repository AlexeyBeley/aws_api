import pdb
from sessions_manager import SessionsManager


class Boto3Client(object):
    EXEC_COUNT = 0
    SESSIONS_MANAGER = SessionsManager()

    def __init__(self, client_name):
        """
        self.client shouldn't be inited, the init should be done on demand if execute is called
        Client is a singleton identified by client_name and region_name

        :param client_name:

        """

        self.client_name = client_name

    @property
    def client(self):
        return self.SESSIONS_MANAGER.get_client(self.client_name)

    @client.setter
    def client(self, _):
        raise RuntimeError("Nobody can set a client explicitly")

    def connect(self):
        """
        Connects relevant clients. If session not connected - connects session too.
        :return:
        """
        if self.SESSIONS_MANAGER.get_current_session() is None:
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
    def start_assuming_role(cls, role_arn):
        SessionsManager.start_assuming_role(role_arn)

    @classmethod
    def stop_assuming_role(cls):
        SessionsManager.stop_assuming_role()

    def execute(self, func_command, return_string, filters_req=None):
        """
        Command to execute clients bound function- execute with paginator if available.

        :param func_command: Bound method from _client instance
        :param return_string: string to retrive the infromation from reply dict
        :param filters_req: filters dict passed to the API client to filter the response
        :return: list of replies
        """
        pdb.set_trace()

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

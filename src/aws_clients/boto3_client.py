import pdb
import time
from sessions_manager import SessionsManager
from h_logger import get_logger

logger = get_logger()


class Boto3Client(object):
    EXEC_COUNT = 0
    SESSIONS_MANAGER = SessionsManager()
    EXECUTION_RETRY_COUNT = 4
    NEXT_PAGE_REQUEST_KEY = "NextToken"
    NEXT_PAGE_RESPONSE_KEY = "NextToken"
    NEXT_PAGE_INITIAL_KEY = None

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

    def yield_with_paginator(self, func_command, return_string, filters_req=None, raw_answer=False):
        """
        Function to yeild replies, if there is no need to get all replies.
        It can save API requests if the expected information found before.

        :param func_command: Bound method from _client instance
        :param return_string: string to retrive the infromation from reply dict
        :param filters_req: filters dict passed to the API client to filter the response
        :return: list of replies
        """
        if raw_answer:
            raise NotImplementedError()

        if filters_req is None:
            filters_req = {}

        starting_token = self.NEXT_PAGE_INITIAL_KEY

        for retry_counter in range(self.EXECUTION_RETRY_COUNT):
            try:
                logger.info(f"Start paginating with starting_token: '{starting_token}' and args '{filters_req}'")

                for _page in self.client.get_paginator(func_command.__name__).paginate(
                        PaginationConfig={self.NEXT_PAGE_REQUEST_KEY: starting_token},
                        **filters_req):

                    starting_token = _page.get(self.NEXT_PAGE_RESPONSE_KEY)
                    logger.info(f"Updating '{func_command.__name__}' pagination starting_token: {starting_token}")

                    Boto3Client.EXEC_COUNT += 1

                    if return_string not in _page:
                        raise NotImplementedError("Has no return string")

                    for response_obj in _page[return_string]:
                        yield response_obj
                    if starting_token is None:
                        return
            except Exception as e:
                time.sleep(1)
                logger.warning(f"Retrying '{func_command.__name__}' attempt {retry_counter}/{self.EXECUTION_RETRY_COUNT} Error: {e}")

    @classmethod
    def start_assuming_role(cls, role_arn):
        SessionsManager.start_assuming_role(role_arn)

    @classmethod
    def stop_assuming_role(cls):
        SessionsManager.stop_assuming_role()

    def execute(self, func_command, return_string, filters_req=None, raw_answer=False):
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
            for ret_obj in self.yield_with_paginator(func_command, return_string, filters_req=filters_req, raw_answer=raw_answer):
                yield ret_obj
            return

        Boto3Client.EXEC_COUNT += 1
        response = func_command(**filters_req)

        if raw_answer:
            yield response
            return

        if type(response[return_string]) is list:
            ret_lst = response[return_string]
        elif type(response[return_string]) in [str, dict]:
            ret_lst = [response[return_string]]
        else:
            raise NotImplementedError("{} type:{}".format(response[return_string], type(response[return_string])))

        for ret_obj in ret_lst:
            yield ret_obj

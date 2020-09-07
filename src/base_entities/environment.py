from region import Region
import pdb
from enum import Enum


class ConnectionStep:
    class Type(Enum):
        AWS_CREDENTIALS = 0
        ASSUME_ROLE = 1

    def __init__(self, dict_src):
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.role_arn = None
        self.region = None

        if "region_mark" in dict_src:
            self.region = Region()
            self.region.region_mark = dict_src["region_mark"]

        if "aws_credentials" in dict_src:
            if dict_src["aws_credentials"] != "default":
                raise NotImplementedError()
        elif "assume_role" in dict_src:
            self.role_arn = dict_src["assume_role"]
        else:
            raise NotImplementedError(f"Unknown {dict_src}")


class Environment:
    _ENVIRONMENT = None

    @staticmethod
    def get_environment():
        return Environment._ENVIRONMENT

    @staticmethod
    def set_environment(value):
        Environment._ENVIRONMENT = value

    def __init__(self):
        self.id = None
        self.connection_steps = []

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        return self.id == other.id

    def init_from_dict(self, dict_src):
        """
        Example:

        :param dict_src:
        :return:
        """
        self.id = dict_src["id"]

        if "connection_steps" in dict_src:
            self._init_connection_steps_from_list(dict_src["connection_steps"])

    def _init_connection_steps_from_list(self, lst_src):
        for connection_step_dict in lst_src:
            connection_step = ConnectionStep(connection_step_dict)
            self.connection_steps.append(connection_step)


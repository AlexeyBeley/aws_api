from region import Region
import pdb
from enum import Enum


class ConnectionStep:
    class Type(Enum):
        CREDENTIALS = 0
        PROFILE = 1
        ASSUME_ROLE = 2

    def __init__(self, dict_src):
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.profile_name = None
        self.role_arn = None
        self.region = None
        self.type = None

        if "region_mark" in dict_src:
            self.region = Region()
            self.region.region_mark = dict_src["region_mark"]

        if "credentials" in dict_src:
            raise NotImplementedError()
        elif "profile" in dict_src:
            self.type = ConnectionStep.Type.PROFILE
            self.profile_name = dict_src["profile"]
        elif "assume_role" in dict_src:
            self.type = ConnectionStep.Type.ASSUME_ROLE
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
        self.region = None
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

        if "region_mark" in dict_src:
            self.region = Region()
            self.region.region_mark = dict_src["region_mark"]

        if "connection_steps" in dict_src:
            self._init_connection_steps_from_list(dict_src["connection_steps"])

    def _init_connection_steps_from_list(self, lst_src):
        for connection_step_dict in lst_src:
            connection_step = ConnectionStep(connection_step_dict)
            self.connection_steps.append(connection_step)


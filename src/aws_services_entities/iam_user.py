import pdb
import re

import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class IamUser(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        """
        Init Iam user with boto3 dict
        :param dict_src:
        """
        super(IamUser, self).__init__(dict_src)
        if from_cache:
            self._init_user_from_cashe(dict_src)
            return

        init_options = {
                        "UserId": lambda x, y: self.init_default_attr(x, y, formatted_name="id"),
                        "Path": self.init_default_attr,
                        "UserName": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                        "Arn": self.init_default_attr,
                        "CreateDate": self.init_default_attr,
                        "PasswordLastUsed": self.init_default_attr}

        self.init_attrs(dict_src, init_options)

    def _init_user_from_cashe(self, dict_src):
        options = {'create_date': self.init_date_attr_from_cache_string,
                   'password_last_used':  self.init_date_attr_from_cache_string}

        self._init_from_cache(dict_src, options)

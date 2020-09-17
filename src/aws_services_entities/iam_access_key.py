import pdb
import re

import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class IamAccessKey(AwsObject):
    def __init__(self, dict_src):
        """
        Init Iam user with boto3 dict
        :param dict_src:
        """
        super(IamAccessKey, self).__init__(dict_src)

        init_options = {
                        "AccessKeyId": lambda x, y: self.init_default_attr(x, y, formatted_name="id"),
                        "UserName": self.init_default_attr,
                        "Status": self.init_default_attr,
                        "CreateDate": self.init_default_attr}

        self.init_attrs(dict_src, init_options)

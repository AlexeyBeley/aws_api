import pdb
import re

import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class IamRole(AwsObject):
    def __init__(self, dict_src):
        """
        Init Iam user with boto3 dict
        :param dict_src:
        """
        super(IamRole, self).__init__(dict_src)

        init_options = {
                        "RoleId": lambda x, y: self.init_default_attr(x, y, formated_name="id"),
                        "Path": self.init_default_attr,
                        "RoleName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "Arn": self.init_default_attr,
                        "CreateDate": self.init_default_attr,
                        "AssumeRolePolicyDocument": self.init_default_attr,
                        "Description": self.init_default_attr,
                        "MaxSessionDuration": self.init_default_attr}

        self.init_attrs(dict_src, init_options)

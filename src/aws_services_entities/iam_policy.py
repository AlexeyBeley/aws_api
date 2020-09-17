import pdb
import re

import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class IamPolicy(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        """
        Init with boto3 dict
        :param dict_src:
        """

        super(IamPolicy, self).__init__(dict_src, from_cache=from_cache)
        if from_cache:
            self._init_policy_from_cashe(dict_src)
            return

        init_options = {
                        "PolicyId": lambda x, y: self.init_default_attr(x, y, formatted_name="id"),
                        "Path": self.init_default_attr,
                        "PolicyName": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                        "Arn": self.init_default_attr,
                        "CreateDate": self.init_default_attr,
                        "DefaultVersionId": self.init_default_attr,
                        "AttachmentCount": self.init_default_attr,
                        "PermissionsBoundaryUsageCount": self.init_default_attr,
                        "IsAttachable": self.init_default_attr,
                        "UpdateDate": self.init_default_attr}

        self.init_attrs(dict_src, init_options)

    def _init_policy_from_cashe(self, dict_src):
        options = {'create_date': self.init_date_attr_from_formatted_string,
                   'update_date':  self.init_date_attr_from_formatted_string}

        self._init_from_cache(dict_src, options)

    def update_statements(self, dict_src):
        init_options = {"CreateDate": self.init_default_attr,
                        "IsDefaultVersion": self.init_default_attr,
                        "VersionId": self.init_default_attr,
                        "Document": self.init_document
                        }

        self.init_attrs(dict_src, init_options)

    def init_document(self, _, value):
        document = IamPolicy.Document(value)
        self.init_default_attr("document", document)

    class Document(AwsObject):
        def __init__(self, dict_src):
            pdb.set_trace()


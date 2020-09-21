import pdb
import re

import sys
import os
from common_utils import CommonUtils
sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class CloudWatchLogGroup(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        """
        Init with boto3 dict
        :param dict_src:
        """

        super(CloudWatchLogGroup, self).__init__(dict_src, from_cache=from_cache)
        if from_cache:
            self._init_cloud_watch_log_group_from_cashe(dict_src)
            return

        init_options = {
                        "logGroupName": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                        "creationTime": self.init_default_attr,
                        "metricFilterCount": self.init_default_attr,
                        "arn": self.init_default_attr,
                        "storedBytes": self.init_default_attr,
                        "retentionInDays": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_policy_from_cashe(self, dict_src):
        options = {}

        self._init_from_cache(dict_src, options)

    def init_document_from_cache(self, key, value):
        self.document = IamPolicy.Document(value, from_cache=True)

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
        def __init__(self, dict_src, from_cache=False):
            self.statements = []

            super(IamPolicy.Document, self).__init__(dict_src, from_cache=from_cache)

            if from_cache:
                self.init_document_from_cache(dict_src)
                return

            init_options = {"Version": self.init_default_attr,
                            "Statement": self.init_statement,
                            "Id": self.init_default_attr,
                            }

            self.init_attrs(dict_src, init_options)

        def init_document_from_cache(self, dict_src):
            options = {"statements": lambda key, value: self.init_statement(key, value, from_cache=True),
                       }

            self._init_from_cache(dict_src, options)

        def init_statement(self, key, lst_src, from_cache=False):
            for dict_src in lst_src:
                try:
                    statement = IamPolicy.Document.Statement(dict_src, from_cache=from_cache)
                except self.ParsingError as e:
                    statement = IamPolicy.Document.Statement(dict())
                    statement.dict_src = {"ParsingError": repr(e)}

                self.statements.append(statement)

        class Statement(AwsObject):
            def __init__(self, dict_src, from_cache=False):
                self.effect = None
                self.actions = {}
                self.resources = None
                super(IamPolicy.Document.Statement, self).__init__(dict_src, from_cache=from_cache)

                if from_cache:
                    self.init_statement_from_cache(dict_src)
                    return

                init_options = {"Sid": self.init_default_attr,
                                "Effect": self.init_effect,
                                "Action": self.init_action,
                                "Resource": self.init_resource,
                                "Condition": self.init_default_attr,
                                "NotAction": self.init_default_attr,
                                "NotResource": self.init_default_attr,
                                }

                if isinstance(dict_src, str):
                    raise self.ParsingError(f"Statement error. Expected dict received str:  {dict_src}")

                self.init_attrs(dict_src, init_options)

            def init_statement_from_cache(self, dict_src):
                options = {}
                self._init_from_cache(dict_src, options)

            def init_action(self, key, value):
                if isinstance(value, str):
                    value = [value]

                if not isinstance(value, list):
                    raise ValueError(value)

                for str_action in value:
                    if ":" not in str_action:
                        if str_action == "*":
                            self.actions[str_action] = str_action
                            continue
                        else:
                            pdb.set_trace()
                            raise NotImplementedError()
                    service_name, action = str_action.split(":", 1)
                    if service_name not in self.actions:
                        self.actions[service_name] = []
                    self.actions[service_name].append(action)

            def init_resource(self, key, value):
                if isinstance(value, str):
                    value = [value]
                elif isinstance(value, list):
                    pass
                else:
                    raise TypeError(type(value))

                self.init_default_attr(key, value, formatted_name="resources")

            def init_effect(self, key, value):
                if value not in ["Allow", "Deny"]:
                    raise ValueError(value)

                self.init_default_attr(key, value)
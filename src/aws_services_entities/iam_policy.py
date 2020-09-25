import pdb
import sys
import os
from enum import Enum

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class IamPolicy(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        """
        Init with boto3 dict
        :param dict_src:
        """
        self.document = None

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
        options = {"create_date": self.init_date_attr_from_formatted_string,
                   "update_date":  self.init_date_attr_from_formatted_string,
                   "document": self.init_document_from_cache,
                   }

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
            if not isinstance(lst_src, list):
                lst_src = [lst_src]

            for dict_src in lst_src:
                statement = IamPolicy.Document.Statement(dict_src, from_cache=from_cache)

                self.statements.append(statement)

        class Statement(AwsObject):
            def __init__(self, dict_src, from_cache=False):
                self.effect = None
                self.action = {}
                self.not_action = {}
                self.resource = None
                self.not_resource = None
                super(IamPolicy.Document.Statement, self).__init__(dict_src, from_cache=from_cache)

                if from_cache:
                    self.init_statement_from_cache(dict_src)
                    return

                init_options = {"Sid": self.init_default_attr,
                                "Effect": self.init_effect,
                                "Action": self.init_action,
                                "Resource": self.init_resource,
                                "Condition": self.init_default_attr,
                                "NotAction": self.init_action,
                                "NotResource": self.init_resource,
                                }

                self.init_attrs(dict_src, init_options)

            def init_statement_from_cache(self, dict_src):
                options = {"effect": self.init_effect}
                self._init_from_cache(dict_src, options)

            def init_action(self, attr_name, value):
                if isinstance(value, str):
                    value = [value]
                action = getattr(self, self.format_attr_name(attr_name))

                if not isinstance(value, list):
                    raise ValueError(value)

                for str_action in value:
                    if ":" not in str_action:
                        if str_action == "*":
                            action[str_action] = str_action
                            continue
                        else:
                            pdb.set_trace()
                            raise NotImplementedError()

                    service_name, action_value = str_action.split(":", 1)

                    if service_name not in action:
                        action[service_name] = []
                    action[service_name].append(action_value)

            def init_resource(self, key, value):
                if isinstance(value, str):
                    value = [value]
                elif isinstance(value, list):
                    pass
                else:
                    raise TypeError(type(value))

                self.init_default_attr(key, value)

            def init_effect(self, key, value):
                for enum_attr in self.Effects:
                    if enum_attr.value == value:
                        self.init_default_attr(key, enum_attr)
                        return
                raise ValueError(value)


            def intersect_resource_value_regex(self, resource_1, resource_2):
                """
                Regex? What is regex? Split them!

                :param resource_1:
                :param resource_2:
                :return:
                """
                lst_ret = []
                pdb.set_trace()
                return lst_ret

            def intersect_resource(self, other):
                lst_ret = []
                for self_resource in self.resource:
                    if self_resource == "*":
                        return [other_resource for other_resource in other.resource]
                    for other_resource in other.resource:
                        if other_resource == "*":
                            return [self_resource for self_resource in self.resource]

                        if "*" in self_resource or "*" in other_resource:
                            lst_ret += self.intersect_resource_value_regex(self_resource, other_resource)
                        elif self_resource == other_resource:
                            lst_ret.append(self_resource)
                return lst_ret

            @staticmethod
            def check_service_intersect(service_name_1, service_name_2):
                if service_name_1 == service_name_2:
                    return True
                pdb.set_trace()

            @staticmethod
            def check_action_intersect(service_name_1, service_name_2):
                if service_name_1 == service_name_2:
                    return True
                pdb.set_trace()

            @staticmethod
            def action_values_intersect(action_1, action_2):
                lst_ret = []
                if "*" in action_1:
                    pdb.set_trace()
                if "*" in action_2:
                    pdb.set_trace()
                if action_1 == action_2:
                    return [action_1]
                return lst_ret

            def action_lists_values_intersect(self, actions_1, actions_2):
                lst_ret = []
                for action_1 in actions_1:
                    for action_2 in actions_2:
                        lst_ret += self.action_values_intersect(action_1, action_2)
                return lst_ret

            def intersect_action(self, other):
                lst_ret = []
                for self_service, self_action in self.action.items():
                    for other_service, other_action in other.action.items():
                        if self.check_service_intersect(self_service, other_service):
                            lst_ret += self.action_lists_values_intersect(self_action, other_action)

                return lst_ret

            class Effects(Enum):
                ALLOW = "Allow"
                DENY = "Deny"

            class Resource:
                """
                ARN built by this specs:
                https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
                """

                def __init__(self, str_src):
                    self.str_src = str_src
                    self.partition = None
                    self.service = None
                    self.region = None
                    self.account_id = None
                    self.resource_type = None
                    self.resource_id = None
                    self.init_from_regex_arn(str_src)

                def init_from_regex_arn(self, arn):
                    """
                    arn:partition:service:region:account-id:resource-id
                    arn:partition:service:region:account-id:resource-type/resource-id
                    arn:partition:service:region:account-id:resource-type:resource-id
                    :param arn:
                    :return:
                    """
                    init_sequance =  {0: self.partition,
                                      1: self.service,
                                      2: self.region,
                                      3: self.account_id,
                                      4: self.resource_type,
                                      5: self.resource_id
                                      }
                    pdb.set_trace()
                    lst_arn = arn.split(":")
                    while len(arn) > 0:

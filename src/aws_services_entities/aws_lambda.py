from dns import DNS
import sys
import os
import pdb

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class AWSLambda(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(AWSLambda, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
            "FunctionName": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
            "FunctionArn": self.init_default_attr,
            "Runtime": self.init_default_attr,
            "Role": self.init_default_attr,
            "Handler": self.init_default_attr,
            "CodeSize": self.init_default_attr,
            "Description": self.init_default_attr,
            "Timeout": self.init_default_attr,
            "MemorySize": self.init_default_attr,
            "LastModified": lambda attr_name, value: self.init_date_attr_from_formatted_string(attr_name, self.format_last_modified_time(value)),
            "CodeSha256": self.init_default_attr,
            "Version": self.init_default_attr,
            "VpcConfig": self.init_default_attr,
            "Environment": self.init_default_attr,
            "TracingConfig": self.init_default_attr,
            "RevisionId": self.init_default_attr,
            "Layers": self.init_default_attr,
            "DeadLetterConfig": self.init_default_attr,
            "KMSKeyArn": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    @staticmethod
    def format_last_modified_time(str_value):
        _date, _time = str_value.split("T")
        _time, _micro_and_zone = _time.split(".")
        _micro_and_zone = "000" + _micro_and_zone
        return f"{_date} {_time}.{_micro_and_zone}"

    def _init_object_from_cache(self, dict_src):
        options = {"last_modified": self.init_date_attr_from_formatted_string,
                   }
        self._init_from_cache(dict_src, options)

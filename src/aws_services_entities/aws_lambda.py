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
            "FunctionName": self.init_default_attr,
            "FunctionArn": self.init_default_attr,
            "Runtime": self.init_default_attr,
            "Role": self.init_default_attr,
            "Handler": self.init_default_attr,
            "CodeSize": self.init_default_attr,
            "Description": self.init_default_attr,
            "Timeout": self.init_default_attr,
            "MemorySize": self.init_default_attr,
            "LastModified": self.init_default_attr,
            "CodeSha256": self.init_default_attr,
            "Version": self.init_default_attr,
            "VpcConfig": self.init_default_attr,
            "Environment": self.init_default_attr,
            "TracingConfig": self.init_default_attr,
            "RevisionId": self.init_default_attr,
            "Layers": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {
                   }
        self._init_from_cache(dict_src, options)

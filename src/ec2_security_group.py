import pdb
import re

import sys
import os
sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))
from ip import IP
from aws_object import AwsObject


class EC2SecurityGroup(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(EC2SecurityGroup, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "GroupName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "Description": self.init_default_attr,
                        "IpPermissions": self.init_default_attr,
                        "OwnerId": self.init_default_attr,
                        "GroupId": lambda x, y: self.init_default_attr(x, y, formated_name="id"),
                        "IpPermissionsEgress": self.init_default_attr,
                        "Tags": self.init_default_attr,
                        "VpcId": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {
                   'created_date':  self.init_date_attr_from_cache_string,
                   }
        self._init_from_cache(dict_src, options)

    def get_dns_records(self):
        ret = [self.dns_name] if self.dns_name else []

        return ret

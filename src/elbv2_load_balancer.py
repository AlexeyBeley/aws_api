import pdb

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class LoadBalancer(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(LoadBalancer, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "LoadBalancerArn": lambda x, y: self.init_default_attr(x, y, formated_name="arn"),
                        "LoadBalancerName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "DNSName": self.init_default_attr,
                        "CanonicalHostedZoneId": self.init_default_attr,
                        "CreatedTime": self.init_default_attr,
                        "Scheme": self.init_default_attr,
                        "VpcId": self.init_default_attr,
                        "State": self.init_default_attr,
                        "Type": self.init_default_attr,
                        "IpAddressType": self.init_default_attr,
                        "AvailabilityZones": self.init_default_attr,
                        "SecurityGroups": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {
                   'created_date':  self.init_date_attr_from_cache_string,
                   }
        self._init_from_cache(dict_src, options)

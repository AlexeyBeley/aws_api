import pdb

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class ELBV2TargetGroup(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(ELBV2TargetGroup, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return
        self.target_health = None
        init_options = {
                        "TargetGroupArn": lambda x, y: self.init_default_attr(x, y, formated_name="arn"),
                        "TargetGroupName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "Protocol": self.init_default_attr,
                        "Port": self.init_default_attr,
                        "VpcId": self.init_default_attr,
                        "HealthCheckProtocol": self.init_default_attr,
                        "HealthCheckPort": self.init_default_attr,
                        "HealthCheckEnabled": self.init_default_attr,
                        "HealthCheckIntervalSeconds": self.init_default_attr,
                        "HealthCheckTimeoutSeconds": self.init_default_attr,
                        "HealthyThresholdCount": self.init_default_attr,
                        "UnhealthyThresholdCount": self.init_default_attr,
                        "HealthCheckPath": self.init_default_attr,
                        "Matcher": self.init_default_attr,
                        "LoadBalancerArns": self.init_default_attr,
                        "TargetType": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {
                   }
        self._init_from_cache(dict_src, options)

    def get_dns_records(self):
        ret = [self.dns_name] if self.dns_name else []

        return ret

    def update_target_health(self, dict_src):
        self.target_health = dict_src

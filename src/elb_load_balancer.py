from dns import DNS
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class ClassicLoadBalancer(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(ClassicLoadBalancer, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "LoadBalancerName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "DNSName": self.init_default_attr,
                        "CanonicalHostedZoneNameID": self.init_default_attr,
                        "ListenerDescriptions": self.init_default_attr,
                        "Policies": self.init_default_attr,
                        "BackendServerDescriptions": self.init_default_attr,
                        "Subnets": self.init_default_attr,
                        "VPCId": self.init_default_attr,
                        "Instances": self.init_default_attr,
                        "HealthCheck": self.init_default_attr,
                        "SourceSecurityGroup": self.init_default_attr,
                        "CreatedTime": self.init_default_attr,
                        "SecurityGroups": self.init_default_attr,
                        "Scheme": self.init_default_attr,
                        "AvailabilityZones": self.init_default_attr,
                        "CanonicalHostedZoneName": self.init_default_attr,
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

    def get_all_addresses(self):
        return [DNS(self.dns_name)]

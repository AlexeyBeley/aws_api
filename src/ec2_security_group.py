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
        self.ip_permissions = []
        self.ip_permissions_egress = []

        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "GroupName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "Description": self.init_default_attr,
                        "IpPermissions": self.init_ip_permissions,
                        "OwnerId": self.init_default_attr,
                        "GroupId": lambda x, y: self.init_default_attr(x, y, formated_name="id"),
                        "IpPermissionsEgress": self.init_ip_permissions,
                        "Tags": self.init_default_attr,
                        "VpcId": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {
                   'created_date':  self.init_date_attr_from_cache_string,
                   'ip_permissions': self.init_ip_permissions_from_cache_string,
                   'ip_permissions_egress': self.init_ip_permissions_from_cache_string,
                   }
        self._init_from_cache(dict_src, options)

    def init_ip_permissions(self, key_name, lst_src):
        lst_ret = [self.IpPermission(dict_src) for dict_src in lst_src]
        if key_name == "IpPermissions":
            self.ip_permissions = lst_ret
        elif key_name == "IpPermissionsEgress":
            self.ip_permissions_egress = lst_ret
        else:
            raise NotImplementedError

    def init_ip_permissions_from_cache_string(self, key_name, lst_src):
        lst_ret = [self.IpPermission(dict_src, from_cache=True) for dict_src in lst_src]
        setattr(self, key_name, lst_ret)
        if key_name == "ip_permissions":
            self.ip_permissions = lst_ret
        elif key_name == "ip_permissions_egress":
            self.ip_permissions_egress = lst_ret

    def convert_to_dict(self):
        custom_types = {self.IpPermission: lambda x: x.convert_to_dict()}
        return self.convert_to_dict_static(self.__dict__, custom_types=custom_types)

    def get_dns_records(self):
        ret = [self.dns_name] if self.dns_name else []

        return ret

    class IpPermission(AwsObject):
        def __init__(self, dict_src, from_cache=False):
            super(EC2SecurityGroup.IpPermission, self).__init__(dict_src)
            self.ipv4_ranges = []
            self.ipv6_ranges = []

            if from_cache:
                self._init_object_from_cache(dict_src)
                return

            init_options = {
                "FromPort": self.init_default_attr,
                "IpProtocol": self.init_default_attr,
                "IpRanges": self.init_ip_addresses,
                "Ipv6Ranges": self.init_ip_addresses,
                "PrefixListIds": self.init_default_attr,
                "ToPort": self.init_default_attr,
                "UserIdGroupPairs": self.init_default_attr,
            }

            self.init_attrs(dict_src, init_options)

        def init_ip_addresses(self, key_name, lst_src):
            for dict_src in lst_src:
                if "CidrIp" in dict_src:
                    ip = IP(dict_src["CidrIp"])
                elif "CidrIpv6" in dict_src:
                    ip = IP(dict_src["CidrIpv6"])
                else:
                    raise NotImplementedError

                description = dict_src["Description"] if "Description" in dict_src else None
                addr = self.Address(ip, description=description)

                if addr.ip.type == IP.Types.IPV4:
                    self.ipv4_ranges.append(addr)
                elif addr.ip.type == IP.Types.IPV6:
                    self.ipv6_ranges.append(addr)
                else:
                    raise NotImplemented

        def _init_object_from_cache(self, dict_src):
            options = {
                'ipv4_ranges': self._init_ip_addresses_from_cache,
                'ipv6_ranges': self._init_ip_addresses_from_cache,
            }
            self._init_from_cache(dict_src, options)

        def _init_ip_addresses_from_cache(self, key_name, lst_src):
            setattr(self, key_name, [self.Address(dict_src["ip"], description=dict_src["description"], from_cache=True) for dict_src in lst_src])

        class Address(AwsObject):
            def __init__(self, ip, description=None, from_cache=False):
                super(EC2SecurityGroup.IpPermission.Address, self).__init__({})
                if from_cache is True:
                    ip = IP(ip, from_dict=True)
                self.ip = ip
                self.description = description

            def convert_to_dict(self):
                custom_types = {IP: lambda x: x.convert_to_dict()}
                return self.convert_to_dict_static(self.__dict__, custom_types=custom_types)

import pdb
import re

import sys
import os

from ip import IP
from aws_object import AwsObject


class EC2VPCSubnet(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(EC2VPCSubnet, self).__init__(dict_src)
        self.tags = []
        self.cidr_block = None

        if from_cache:
            self._init_object_from_cache(dict_src)
            return
        init_options = {
                        "SubnetId": lambda x, y: self.init_default_attr(x, y, formated_name="id"),
                        "Tags": self.init_default_attr,
                        "VpcId": self.init_default_attr,
                        "OwnerId": self.init_default_attr,
                        "AvailabilityZone": self.init_default_attr,
                        "AvailabilityZoneId": self.init_default_attr,
                        "AvailableIpAddressCount": self.init_default_attr,
                        "CidrBlock": self.init_cidr_block,
                        "DefaultForAz": self.init_default_attr,
                        "MapPublicIpOnLaunch": self.init_default_attr,
                        "State": self.init_default_attr,
                        "AssignIpv6AddressOnCreation": self.init_default_attr,
                        "Ipv6CidrBlockAssociationSet": self.init_default_attr,
                        "SubnetArn": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

        for tag in self.tags:
            if tag["Key"] == "Name":
                self.name = tag["Value"]
                break
        else:
            self.name = self.id

    def init_cidr_block(self, _, dict_src):
        self.cidr_block = IP(dict_src)

    def _init_object_from_cache(self, dict_src):
        options = {
            'cidr_block': self._init_cidr_block_from_cache,
        }
        self._init_from_cache(dict_src, options)

    def _init_cidr_block_from_cache(self, _, value):
        if self.cidr_block is not None:
            raise NotImplementedError
        else:
            self.cidr_block = IP(value, from_dict=True)

    def convert_to_dict(self):
        custom_types = {IP: lambda x: x.convert_to_dict()}
        return self.convert_to_dict_static(self.__dict__, custom_types=custom_types)

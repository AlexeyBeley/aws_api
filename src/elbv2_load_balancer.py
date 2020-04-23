from dns import DNS

from aws_object import AwsObject
from common_utils import CommonUtils

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

    def get_dns_records(self):
        """
        Get dns fqdn pointing this db

        :return:
        """
        ret = [self.dns_name] if self.dns_name else []

        return ret

    def get_security_groups_endpoints(self):
        """
        Get sg ids, specified in this lb

        :return:
        """
        ret = []
        grps = self.__dict__.get("security_groups")
        grps = grps if grps is not None else []

        for sg in grps:
            endpoint = {"sg_id": sg}
            endpoint["dns"] = DNS(self.dns_name)
            endpoint["description"] = "lb: {}".format(self.name)
            ret.append(endpoint)

        return ret

    def get_all_networks(self, vpc_subnets):
        lst_ret = []
        for zone in self.availability_zones:
            if zone["LoadBalancerAddresses"] != [{}]:
                raise Exception
            lst_ret.append(CommonUtils.find_objects_by_values(vpc_subnets, {"id": zone["SubnetId"]}, max_count=1)[0].cidr_block)
        return lst_ret

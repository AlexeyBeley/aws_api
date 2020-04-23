import json
import pdb
import os
import socket
import datetime

from enum import Enum
from ip import IP
from text_block import TextBlock

from ec2_client import EC2Client
from ec2_instance import EC2Instance
from ec2_security_group import EC2SecurityGroup
from ec2_vpc_subnet import EC2VPCSubnet

from cloudwatch_logs_client import CloudWatchLogsClient
from cloudwatch_log_group import CloudwatchLogGroup

from s3_client import S3Client
from s3_bucket import S3Bucket

from elbv2_client import ELBV2Client
from elbv2_load_balancer import LoadBalancer
from elbv2_target_group import ELBV2TargetGroup

from elb_client import ELBClient
from elb_load_balancer import ClassicLoadBalancer

from route53_client import Route53Client
from route53_hosted_zone import HostedZone

from rds_client import RDSClient
from rds_db_instance import DBInstance

from iam_client import IamClient
from iam_policy import IamPolicy
from iam_user import IamUser

from common_utils import CommonUtils
from collections import defaultdict
from dns import DNS


class Service(object):
    ANY = None

    @classmethod
    def any(cls):
        if Service.ANY is None:
            Service.ANY = Service()
        return Service.ANY

    def __init__(self):
        pass

    def __str__(self):
        if self is Service.any():
            return "any"
        raise NotImplementedError

    def copy(self):
        if self is self.any():
            return self.any()

        raise NotImplementedError

    def intersect(self, other):
        if not isinstance(other, Service):
            raise ValueError
        pdb.set_trace()


class ServiceTCP(Service):
    def __init__(self):
        super(ServiceTCP, self).__init__()
        self._start = None
        self._end = None

    def __str__(self):
        return "TCP:[{}-{}]".format(self.start, self.end)

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self.check_range(value)

        if self.end:
            self.check_order(value, self.end)

        self._start = value

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value):
        self.check_range(value)

        if self.start:
            self.check_order(self.start, value)

        self._end = value

    def check_range(self, value):
        if value < 0 or value > 65535:
            raise ValueError("Port should be in range 0-65535, received {}".format(value))

    def check_order(self, start, end):
        if start > end:
            raise ValueError("Port start {} > Port end {}".format(start, end))

    def copy(self):
        service = ServiceTCP()
        service.start = self.start
        service.end = self.end
        return service


class ServiceUDP(Service):
    def __init__(self):
        super(ServiceUDP, self).__init__()
        self.start = None
        self.end = None

    def __str__(self):
        return "UDP:[{}-{}]".format(self.start, self.end)

    def copy(self):
        service = Service()
        service.start = self.start
        service.end = self.end
        return service


class ServiceICMP(Service):
    def __init__(self):
        super(ServiceICMP, self).__init__()

    def __str__(self):
        raise NotImplementedError
        return "UDP:[{}-{}]".format(self.start, self.end)


class HFlowFilter(object):
    def __init__(self):
        self.src = self.TunnelEdgeFilter()
        self.dst = self.TunnelEdgeFilter()
        self.info = None

    def __str__(self):
        return "src:{}\ndst: {}".format(self.src, self.dst)

    class TunnelEdgeFilter(object):
        def __init__(self):
            self.ip = None
            self.service = None
            self.dns = None

        def __str__(self):
            return "{},{},{}".format(self.ip, self.dns, self.service)


class HFlow(object):
    def __init__(self):
        self.tunnel = None
        self.end_point_src = None
        self.end_point_dst = None

    def __str__(self):
        ret = "{} -> {}\n".format(str(self.end_point_src), str(self.end_point_dst))
        ret += "\n{}".format(str(self.tunnel))
        return ret

    def apply_dst_filters_on_start(self, h_filters):
        lst_ret = []
        for h_filter in h_filters:
            #print("{}:{}".format(h_filter.info[0], h_filter.info[1]))
            lst_ret += self.apply_dst_filter_on_start(h_filter)

        #for x in lst_ret:
        #    print(x)
        return lst_ret

    def apply_dst_filter_on_start(self, h_filter):
        lst_ret = []

        for traffic_start, traffic_end in self.tunnel.traffic_start.apply_dst_filter(h_filter):
            if traffic_start is None or traffic_end is None:
                continue

            h_flow_ret = HFlow()
            h_flow_ret.end_point_src = self.end_point_src
            h_flow_ret.end_point_dst = self.end_point_dst
            h_flow_ret.tunnel = HFlow.Tunnel(traffic_start=traffic_start, traffic_end=traffic_end)
            lst_ret.append(h_flow_ret)

        return lst_ret

    def copy(self, copy_src_traffic_to_dst=False):
        ret = HFlow()
        ret.tunnel = self.tunnel.copy(copy_src_traffic_to_dst=copy_src_traffic_to_dst)
        ret.end_point_src = self.end_point_src.copy()
        ret.end_point_dst = self.end_point_dst.copy()
        return ret

    class EndPoint(object):
        """
        Hflow endpoint- maybe src, maybe dst.
        This is abstract object representing hflow next stop.

        """
        def __init__(self):
            self._ip = None
            self._dns = None
            self.custom = {}

        @property
        def ip(self):
            return self._ip

        @ip.setter
        def ip(self, ip):
            if self._ip is not None:
                raise Exception("IP can be single instance")
            self._ip = ip

        @property
        def dns(self):
            return self._dns

        @dns.setter
        def dns(self, dns):
            if self._dns is not None:
                raise Exception("IP can be single instance")
            self._dns = dns

        def add_custom(self, key, value):
            """

            :param key:
            :param value: if can include multiple destinations, should implement __add__
            :return:
            """
            if key in self.custom:
                self.custom[key].add(value)
            else:
                self.custom[key] = value

        def copy(self):
            ret = HFlow.EndPoint()
            if self.ip is not None:
                ret._ip = self.ip.copy()
            if self.dns is not None:
                ret._dns = self.dns.copy()

            ret.custom = self.custom

    class Tunnel(object):
        def __init__(self, traffic_start=None, traffic_end=None):
            self.traffic_start = traffic_start
            self.traffic_end = traffic_end

        def __str__(self):
            return "{} ==>\n==> {}".format(str(self.traffic_start), str(self.traffic_end))

        class Traffic(object):
            ANY = None

            def __init__(self):
                self.ip_src = self.any()
                self.ip_dst = self.any()

                self.dns_src = self.any()
                self.dns_dst = self.any()

                self.service_src = self.any()
                self.service_dst = self.any()

            def __str__(self):
                return "[ip:{} , dns:{} , service:{} -> ip:{} , dns:{} , service:{}]".format(self.ip_src, self.dns_src, self.service_src, self.ip_dst, self.dns_dst, self.service_dst)

            def intersect(self, self_end_point, other_end_point):
                if self_end_point is self.any():
                    return other_end_point
                return self_end_point.intersect(other_end_point)

            def apply_dst_filter(self, h_filter):
                ip_src_intersect = self.intersect(self.ip_src, h_filter.ip_src)
                if ip_src_intersect is None:
                    return []

                service_src_intersect = self.intersect(self.service_src, h_filter.service_src)
                if service_src_intersect is None:
                    return []

                ip_dst_intersect = self.intersect(self.ip_dst, h_filter.ip_dst)
                if ip_dst_intersect is None:
                    return []

                service_dst_intersect = self.intersect(self.service_dst, h_filter.service_dst)
                if service_dst_intersect is None:
                    return []

                traffic_start = self.copy()
                traffic_start.ip_src = ip_src_intersect
                traffic_start.service_src = service_src_intersect

                if h_filter.dns_src != self.dns_src:
                    raise NotImplementedError

                if h_filter.dns_dst != self.dns_dst:
                    raise NotImplementedError

                traffic_end = HFlow.Tunnel.Traffic()
                traffic_end.ip_src = traffic_start.ip_src
                traffic_end.dns_src = traffic_start.dns_src
                traffic_end.service_src = traffic_start.service_src

                traffic_end.ip_dst = ip_dst_intersect
                traffic_end.dns_dst = traffic_start.dns_dst
                traffic_end.service_dst = service_dst_intersect
                return [(traffic_start, traffic_end)]

            def copy(self):
                ret = HFlow.Tunnel.Traffic()

                if self.ip_src is not None:
                    ret.ip_src = self.ip_src.copy()

                if self.dns_src is not None:
                    ret.dns_src = self.dns_src.copy()

                if self.ip_dst is not None:
                    ret.ip_dst = self.ip_dst.copy()

                if self.dns_dst is not None:
                    ret.dns_dst = self.dns_dst.copy()

                if self.service_src is not None:
                    ret.service_src = self.service_src.copy()

                if self.service_dst is not None:
                    ret.service_dst = self.service_dst.copy()

                return ret

            def any(self):
                if HFlow.Tunnel.Traffic.ANY is None:
                    HFlow.Tunnel.Traffic.ANY = HFlow.Tunnel.Traffic.Any()
                return HFlow.Tunnel.Traffic.ANY

            class Any(object):
                def __str__(self):
                    return "any"

                def copy(self):
                    return HFlow.Tunnel.Traffic.ANY

                def intersect(self, other):
                    return other

        def copy(self, copy_src_traffic_to_dst=False):
            ret = HFlow.Tunnel()
            ret.traffic_start = self.traffic_start.copy()

            if copy_src_traffic_to_dst:
                ret.traffic_end = self.traffic_start.copy()
            else:
                ret.traffic_end = self.traffic_end.copy()

            return ret

        def repr_in(self):
            return "[ip:{} , dns:{} , service:{}]".format(self.ip_src, self.dns_src, self.service_src)

        def repr_out(self):
            return "[ip:{} , dns:{} , service:{}]".format(self.ip_dst, self.dns_dst, self.service_dst)


class DNSMapNode(object):
    POINTER = "pointer"
    RESOURCE = "res"

    def __init__(self):
        self.type = None  # str resource/pointer
        self.children = []
        self.next = None
        self.data = None
        self.hosted_zone = None  # self hosted zone
        self.destination = None  # the dns_name, used to point this pointer (for example multiple names for server will generate multiple nodes with the same data)

    def get_dephs(self):
        pdb.set_trace()
        return 1 + len(self.children) if self.next else 1


class DNSMap(object):
    def __init__(self, hosted_zones):
        self.nodes = {}
        self.hosted_zones = hosted_zones
        self.unmapped_records = []

    def add_resource_node(self, dns_name, seed):
        if dns_name != dns_name.rstrip("."):
            pdb.set_trace()
            raise Exception

        dns_name = dns_name.rstrip(".")
        if dns_name in self.nodes:
            pdb.set_trace()
            raise Exception(dns_name)

        node = DNSMapNode()
        node.data = seed
        node.type = DNSMapNode.RESOURCE
        node.destination = dns_name
        self.nodes[dns_name] = node

    def add_pointer_node(self, dns_name, hosted_zone, record, pointed_dns):
        """

        :param dns_name: the dns_name this DNSMapNode is being pointed by
        :param hosted_zone:
        :param record: The dns record used to create the data.
        :param pointed_dns:  The dns_name this DNSMapNode points to
        :return:
        """
        if pointed_dns not in self.nodes:
            raise Exception

        dns_name = dns_name.rstrip(".")
        if dns_name in self.nodes:
            # Problem when dns record points to multiple destinations
            for child in self.nodes[dns_name].children:
                if child.pointed_name == pointed_dns:
                    raise Exception

        node = DNSMapNode()
        node.data = record
        node.type = DNSMapNode.POINTER
        node.next = self.nodes[pointed_dns]
        node.destination = dns_name
        node.hosted_zone = hosted_zone
        self.nodes[dns_name] = node

    def prepare_map_add_atype_records(self, dict_types):
        atype_records = [x for x in dict_types["A"]]
        for hz, seed in atype_records:

            if hasattr(seed, "alias_target"):
                continue

            if hasattr(seed, "resource_records"):
                self.add_resource_node(seed.name.rstrip("."), seed)
            else:
                raise Exception

    def prepare_map(self):
        dict_types = self.split_records_by_type()
        self.prepare_map_add_atype_records(dict_types)

        left_dns_records = [x for x in dict_types["CNAME"]] + [x for x in dict_types["A"] if hasattr(x, "alias_target")] + [x for x in dict_types["SRV"]]
        self.unmapped_records = self.recursive_prepare_map(left_dns_records)

    def get_pointed_dns_addresses(self, record):
        if record.type == "CNAME":
            if len(record.resource_records) != 1:
                raise Exception

            pointed_dnss = [record.resource_records[0]["Value"].rstrip(".")]
        elif record.type == "A":
            if not hasattr(record, "alias_target"):
                raise Exception
            if not record.alias_target:
                raise Exception

            pointed_dnss = [record.alias_target["DNSName"].rstrip(".")]
        elif record.type == "SRV":
            if not hasattr(record, "resource_records"):
                raise Exception

            pointed_dnss = [rr["Value"].rsplit(" ", 1)[-1].rstrip(".") for rr in record.resource_records]
        else:
            pdb.set_trace()
            raise Exception

        return pointed_dnss

    def recursive_prepare_map(self, unmapped_dns_records):
        if not unmapped_dns_records:
            return []
        new_unmapped_dns_records = []

        for hosted_zone, record in unmapped_dns_records:
            pointed_dnss = self.get_pointed_dns_addresses(record)

            add_to_new_unmapped_dns_records = False
            for pointed_dns in pointed_dnss:
                if pointed_dns in self.nodes:
                    self.add_pointer_node(record.name, hosted_zone, record, pointed_dns)
                else:
                    add_to_new_unmapped_dns_records = True

            if add_to_new_unmapped_dns_records:
                new_unmapped_dns_records.append([hosted_zone, record])

        print(len(unmapped_dns_records))

        if len(unmapped_dns_records) != len(new_unmapped_dns_records):
            return self.recursive_prepare_map(new_unmapped_dns_records)

        return new_unmapped_dns_records

    def split_records_by_type(self):
        dict_types = {}
        for hz in self.hosted_zones:
            for record in hz.records:
                if record.type not in dict_types:
                    dict_types[record.type] = []
                dict_types[record.type].append((hz, record))
        return dict_types


class SecurityGroupMapEdge(object):
    def __init__(self, edge_type, value, ip_protocol, from_port, to_port, description):
        self.type = edge_type
        self.dst = value
        self.ip_protocol = ip_protocol
        self.from_port = from_port
        self.to_port = to_port
        self.description = description
        self._service = None

    def __str__(self):
        return "SecurityGroupMapEdge: {} {} {} {} {} {} {}".format(
            self.type, self.dst, self.ip_protocol, self.from_port, self.to_port, self.description, self._service)

    @property
    def service(self):
        if self._service is None:
            if self.ip_protocol == '-1':
                if self.from_port is not None or self.to_port is not None:
                    raise Exception
                self._service = Service.any()
            else:
                if self.ip_protocol.lower() == "tcp":
                    self._service = ServiceTCP()
                    self._service.start = self.from_port
                    self._service.end = self.to_port
                elif self.ip_protocol.lower() == "udp":
                    self._service = ServiceUDP()
                    self._service.start = self.from_port
                    self._service.end = self.to_port
                elif self.ip_protocol.lower() == "icmp":
                    self._service = ServiceICMP()
                else:
                    pdb.set_trace()
                    raise ValueError

        return self._service

    @service.setter
    def service(self, value):
        raise NotImplementedError

    class Type(Enum):
        """
            Possible Security group values
        """

        SECURITY_GROUP = 0
        IP = 1


class SecurityGroupMapNode(object):
    def __init__(self, security_group):
        self.security_group = security_group
        self.outgoing_edges = []
        self.incoming_edges = []
        self.data = []
        self._h_flow_filters_dst_only_ip = None
        self._h_flow_filters_dst = None
        self._h_flow_filters_src_only_ip = None
        self._h_flow_filters_src = None

        for permission in self.security_group.ip_permissions:
            self.add_edges_from_permission(self.incoming_edges, permission)

        for permission in self.security_group.ip_permissions_egress:
            self.add_edges_from_permission(self.outgoing_edges, permission)

    def h_flow_filters_dst(self, nodes, only_ip=False):
        if only_ip:
            if self._h_flow_filters_dst_only_ip is not None:
                return self._h_flow_filters_dst_only_ip
            self._h_flow_filters_dst_only_ip = []
            lst_filters = self._h_flow_filters_dst_only_ip
        else:
            if self._h_flow_filters_dst is not None:
                return self._h_flow_filters_dst
            self._h_flow_filters_dst = []
            lst_filters = self._h_flow_filters_dst

        for data_unit in self.data:
            for edge in self.outgoing_edges:
                if edge.type is SecurityGroupMapEdge.Type.IP:

                    h_filter = HFlow.Tunnel.Traffic()

                    h_filter.info = [data_unit, edge]

                    h_filter.dns_src = data_unit["dns"]
                    if "ip" not in data_unit:
                        ip = AWSAPI.find_ips_from_dns(h_filter.dns_src)[0]
                    else:
                        ip = data_unit["ip"]

                    h_filter.ip_src = ip

                    h_filter.ip_dst = edge.dst
                    h_filter.service_dst = edge.service

                    lst_filters.append(h_filter)
                elif edge.type is SecurityGroupMapEdge.Type.SECURITY_GROUP:
                    if only_ip:
                        pdb.set_trace()

                    remote_filters_src = nodes[edge.dst].h_flow_filters_src(nodes, only_ip=True)
                    if not remote_filters_src:
                        continue

                    ip_src = data_unit.get("ip")
                    dns_src = data_unit.get("dns")
                    for remote_filter in remote_filters_src:
                        if remote_filter.ip_src is None:
                            continue
                        if ip_src.intersect(remote_filter.ip_src):
                            pdb.set_trace()
                            raise Exception

                    pdb.set_trace()
                    raise Exception

                else:
                    raise ValueError

        if only_ip:
            self._h_flow_filters_dst_only_ip = lst_filters
            return self._h_flow_filters_dst_only_ip
        else:
            self._h_flow_filters_dst = lst_filters
            return self._h_flow_filters_dst

    def h_flow_filters_src(self, nodes, only_ip=False):
        if only_ip:
            if self._h_flow_filters_src_only_ip is not None:
                return self._h_flow_filters_src_only_ip
            self._h_flow_filters_src_only_ip = []
            lst_filters = self._h_flow_filters_src_only_ip
        else:
            if self._h_flow_filters_src is not None:
                return self._h_flow_filters_src
            self._h_flow_filters_src = []
            lst_filters = self._h_flow_filters_src

        for data_unit in self.data:

            for edge in self.incoming_edges:
                if edge.type is SecurityGroupMapEdge.Type.IP:
                    h_filter = HFlow.Tunnel.Traffic()

                    h_filter.info = [data_unit, edge]

                    h_filter.ip_src = edge.dst
                    h_filter.dns_dst = data_unit["dns"]
                    if "ip" not in data_unit:
                        ip = AWSAPI.find_ips_from_dns(h_filter.dns_dst)[0]
                    else:
                        ip = data_unit["ip"]

                    h_filter.ip_dst = ip

                    h_filter.service_dst = edge.service
                    lst_filters.append(h_filter)

                elif edge.type is SecurityGroupMapEdge.Type.SECURITY_GROUP:
                    if only_ip:

                        all_addresses = nodes[edge.dst].get_all_addresses()
                        for dict_addr in all_addresses:
                            h_filter = HFlow.Tunnel.Traffic()

                            h_filter.info = [data_unit, edge]

                            h_filter.dns_src = dict_addr["dns"]
                            h_filter.dns_dst = data_unit["dns"]
                            if "ip" not in data_unit:
                                ip = AWSAPI.find_ips_from_dns(h_filter.dns_dst)[0]
                            else:
                                ip = data_unit["ip"]

                            h_filter.ip_dst = ip
                            h_filter.ip_src = dict_addr["ip"]

                            h_filter.service_dst = edge.service
                            lst_filters.append(h_filter)
                    else:
                        raise NotImplementedError

                else:
                    raise ValueError

        if only_ip:
            self._h_flow_filters_src_only_ip = lst_filters
            return self._h_flow_filters_src_only_ip
        else:
            self._h_flow_filters_src = lst_filters
            return self._h_flow_filters_src

    def add_edges_from_permission(self, dst_lst, permission):
        """

        :param dst_lst:
        :param permission: Security Group Permissions
        :return:
        """
        lst_ret = []
        edge_type = SecurityGroupMapEdge.Type.SECURITY_GROUP
        for dict_pair in permission.user_id_group_pairs:
            description = dict_pair["GroupName"] if "GroupName" in dict_pair else None
            description = dict_pair["Description"] if "Description" in dict_pair else description
            for key in dict_pair:
                if key not in ["Description", "GroupId", "UserId", "GroupName"]:
                    raise Exception(key)
            lst_ret.append((edge_type, dict_pair["GroupId"], description))

        edge_type = SecurityGroupMapEdge.Type.IP
        for addr in permission.ipv4_ranges:
            lst_ret.append((edge_type, addr.ip, addr.description))

        for addr in permission.ipv6_ranges:
            lst_ret.append((edge_type, addr.ip, addr.description))

        for edge_type, value, description in lst_ret:
            ip_protocol = permission.ip_protocol if hasattr(permission, "ip_protocol") else None
            from_port = permission.from_port if hasattr(permission, "from_port") else None
            to_port = permission.to_port if hasattr(permission, "to_port") else None

            edge = SecurityGroupMapEdge(edge_type, value, ip_protocol, from_port, to_port, description)
            dst_lst.append(edge)

        if permission.prefix_list_ids:
            raise Exception

    def add_data(self, data):
        self.data.append(data)

    def get_all_addresses(self):
        lst_ret = []

        for data in self.data:
            dict_addr = {"ip": None, "dns": None}
            try:
                dict_addr["ip"] = data["ip"]
            except KeyError:
                dict_addr["dns"] = data["dns"]
            lst_ret.append(dict_addr)
        return lst_ret


class SecurityGroupsMap(object):
    def __init__(self):
        self.nodes = {}

    def add_node(self, node):
        if node.security_group.id in self.nodes:
            raise Exception

        self.nodes[node.security_group.id] = node

    def add_node_data(self, security_group_id, data):
        try:
            self.nodes[security_group_id].add_data(data)
        except Exception as e:
            print("todo: remove ' def add_node_data'")

    def find_outgoing_paths(self, sg_id, seen_grps=None):
        if seen_grps is None:
            seen_grps = []
        pdb.set_trace()

    def apply_dst_h_flow_filters_multihop(self, h_flow):

        return self.recursive_apply_dst_h_flow_filters_multihop(h_flow, [], [])

    def apply_dst_h_flow_filters(self, h_flow):
        lst_ret = []
        node = self.nodes[h_flow.end_point_src.custom["security_group_id"]]
        for edge in node.outgoing_edges:
            if edge.type == SecurityGroupMapEdge.Type.IP:
                lst_h_flows = h_flow.apply_dst_filters_on_start(node.h_flow_filters_dst(self.nodes))
                lst_ret += lst_h_flows
            elif edge.type == SecurityGroupMapEdge.Type.SECURITY_GROUP:
                if not self.nodes[edge.dst].data:
                    print("self.nodes[edge.dst] is empty: {}".format(self.nodes[edge.dst]))
                    continue

                pdb.set_trace()
                raise NotImplementedError
            else:
                pdb.set_trace()
                raise NotImplementedError
        return lst_ret

    def recursive_apply_dst_h_flow_filters_multihop(self, h_flow, lst_path, lst_seen):
        node = self.nodes[h_flow.end_point_src.custom["security_group_id"]]

        if node.security_group.id in lst_seen:
            pdb.set_trace()
            raise Exception("todo: loop")
        lst_seen.append(node.security_group.id)
        lst_path.append(node.security_group.id)
        for edge in node.outgoing_edges:
            if edge.type == SecurityGroupMapEdge.Type.IP:
                lst_h_flows = h_flow.apply_dst_filters_on_start(node.h_flow_filters_dst)
                lst_path.append(edge.dst)
            elif edge.type == SecurityGroupMapEdge.Type.SECURITY_GROUP:
                pdb.set_trace()
                lst_h_flows = self.recursive_apply_dst_h_flow_filters_multihop(self.nodes[edge.dst], lst_path, [])

                lst_path
            else:
                pdb.set_trace()
                raise NotImplementedError


class AWSAPI(object):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        self.logger = logger
        self.aws_key_id = aws_key_id
        self.aws_access_secret = aws_access_secret
        self.iam_client = IamClient(aws_key_id, aws_access_secret, region_name, logger)
        self.ec2_client = EC2Client(aws_key_id, aws_access_secret, region_name, logger)
        self.s3_client = S3Client(aws_key_id, aws_access_secret, region_name, logger)
        self.elbv2_client = ELBV2Client(aws_key_id, aws_access_secret, region_name, logger)
        self.elb_client = ELBClient(aws_key_id, aws_access_secret, region_name, logger)
        self.rds_client = RDSClient(aws_key_id, aws_access_secret, region_name, logger)
        self.route53_client = Route53Client(aws_key_id, aws_access_secret, region_name, logger)
        self.cloudwatch_log_client = CloudWatchLogsClient(aws_key_id, aws_access_secret, region_name, logger)
        self.policies = []
        self.ec2_instances = []
        self.s3_buckets = []
        self.load_balancers = []
        self.classic_load_balancers = []
        self.hosted_zones = []
        self.users = []
        self.databases = []
        self.security_groups = []
        self.target_groups = []
        self.vpc_subnets = []
        self.cloudwatch_log_groups = []

    def init_ec2_instances(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, EC2Instance)
        else:
            objects = self.ec2_client.get_all_instances()

        self.ec2_instances = objects

    def init_users(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, IamUser)
        else:
            objects = self.iam_client.get_all_users()

        self.users = objects

    def init_policies(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, IamPolicy)
        else:
            objects = self.iam_client.get_all_policies()

        self.policies = objects

    def init_s3_buckets(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, S3Bucket)
        else:
            objects = self.s3_client.get_all_buckets()

        self.s3_buckets = objects

    def init_load_balancers(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, LoadBalancer)
        else:
            objects = self.elbv2_client.get_all_load_balancers()

        self.load_balancers = objects

    def init_classic_load_balancers(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, ClassicLoadBalancer)
        else:
            objects = self.elb_client.get_all_load_balancers()

        self.classic_load_balancers = objects

    def init_hosted_zones(self, from_cache=False, cache_file=None, full_information=True):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, HostedZone)
        else:
            objects = self.route53_client.get_all_hosted_zones(full_information=full_information)

        self.hosted_zones = objects

    def init_databases(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, DBInstance)
        else:
            objects = self.rds_client.get_all_databases()

        self.databases = objects

    def init_target_groups(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, ELBV2TargetGroup)
        else:
            objects = self.elbv2_client.get_all_target_groups()

        self.target_groups = objects

    def init_vpc_subnets(self, from_cache=False, cache_file=None, full_information=False):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, EC2VPCSubnet)
        else:
            objects = self.ec2_client.get_all_vpc_subnets(full_information=full_information)

        self.vpc_subnets = objects

    def init_cloudwatch_logs(self, from_cache=False, cache_file=None, full_information=False):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, CloudwatchLogGroup)
        else:
            objects = self.cloudwatch_log_client.get_all_log_groups(full_information=full_information)

        self.cloudwatch_log_groups = objects

    def init_security_groups(self, from_cache=False, cache_file=None, full_information=False):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, EC2SecurityGroup)
        else:
            objects = self.ec2_client.get_all_security_groups(full_information=full_information)
        self.security_groups = objects

    def load_objects_from_cache(self, file_name, class_type):
        with open(file_name) as fil:
            return [class_type(dict_src, from_cache=True) for dict_src in json.load(fil)]

    def cache_objects(self, objects, file_name):
        objects_dicts = [obj.convert_to_dict() for obj in objects]

        if not os.path.exists(os.path.dirname(file_name)):
            os.makedirs(os.path.dirname(file_name))

        with open(file_name, "w") as fil:
            try:
                fil.write(json.dumps(objects_dicts))
            except Exception as e:
                pdb.set_trace()
                from aws_cleaner import AWSCleaner
                AWSCleaner(self).cleanup_report_s3_buckets()

    def delete_cloudwatch_logs(self, delete_list, dry_run=True):
        """
        Tries to delete each pair from delete_list synchronously.
        Returns list of successfully deleted pairs.
        If fails on one, continues to the next.

        :param delete_list:
        :param dry_run:
        :return:
        """

        failed_to_delete = []

        if dry_run:
            with open("going_to_delete.txt", "w") as fil:
                for group_name, stream_names_dict in delete_list:
                    for stream_name, lst_date in stream_names_dict.items():
                        fil.write("group_name '{}' stream_name '{}' date '{}'\n".format(group_name, stream_name, lst_date[0]))
            return

        for group_name, stream_names_dict in delete_list:
            pdb.set_trace()
            if len(stream_names_dict) == 0:
                try:
                    if not self.cloudwatch_log_client.delete_log_group(group_name):
                        failed_to_delete.append((group_name, stream_names_dict))
                except Exception as e:
                    if "The specified log group does not exist" in repr(e):
                        self.logger.warning("Cloudwatch LogGroup '{}' doesn't exist".format(group_name))
                    else:
                        raise
            else:
                failed_stream_names = self.cloudwatch_log_client.delete_log_streams(group_name, stream_names_dict)
                if failed_stream_names:
                    failed_to_delete.append((group_name, failed_stream_names))

        return failed_to_delete

    def synchronous_export_cloudwatch_logs(self, export_list, upload_s3_bucket_name, bucket_prefix):
        """
        Tries to export each pair from export_list synchronously.
        Returns list of pairs failed to be exported.
        If fails on one, continues to the next.

        :param export_list:
        :param upload_s3_bucket_name:
        :param bucket_prefix:
        :return:
        """
        len_export_list = len(export_list)
        count_streams = sum([len(streams) for group, streams in export_list])

        self.logger.info("Going to export cloudwatch streams. Groups: {} Streams: {}".format(len_export_list, count_streams))
        pdb.set_trace()

        counter_processed_streams = 0
        failed_to_export = []
        for i in range(len_export_list):
            self.logger.info("Finished processing {} CloudWatch Log Groups, {} Streams".format(i, counter_processed_streams))
            group_name, stream_names = export_list[i]
            try:
                counter_processed_streams += len(stream_names)
                failed_to_export_streams = self.cloudwatch_log_client.synchronous_export_task(upload_s3_bucket_name, bucket_prefix, group_name, stream_names)

                if failed_to_export_streams:
                    failed_to_export += failed_to_export_streams

            except Exception as e:
                failed_to_export.append((group_name, stream_names))
                self.logger.error("failed to synchronously upload group {} streams {} with error {}".format(group_name, stream_names, repr(e)))

        return failed_to_export

    def _get_down_instances(self):
        ret = []
        for instance in self.ec2_instances:
            # 'state', {'Code': 80, 'Name': 'stopped'})
            if instance.state["Name"] in ["terminated", "stopped"]:
                ret.append(instance)
        return ret

    def prepare_hosted_zones_mapping(self):
        dns_map = DNSMap(self.hosted_zones)
        seed_end_points = []

        for inst in self.ec2_instances:
            seed_end_points.append(inst)

        for db in self.databases:
            seed_end_points.append(db)

        for lb in self.load_balancers:
            seed_end_points.append(lb)

        for lb in self.classic_load_balancers:
            seed_end_points.append(lb)

        for seed in seed_end_points:
            for dns_name in seed.get_dns_records():
                dns_map.add_resource_node(dns_name, seed)

        dns_map.prepare_map()
        return dns_map

    def cleanup_report(self):
        # todo: check lambda cost vs instance
        ret = self.cleanup_report_cloudwatch_logs()

        ret = self.cleanup_load_balancers()
        ret = self.cleanup_target_groups()
        pdb.set_trace()
        ret = self.cleanup_report_ec2_paths()
        pdb.set_trace()
        ret = self.cleanup_report_security_groups()
        ret = self.cleanup_report_dns_records()

        return ret

    def cleanup_report_cloudwatch_logs(self):
        ret = TextBlock("Cloudwatch logs report")

        ret.blocks.append(self.cleanup_report_cloudwatch_logs_by_all_log_dates())

        ret.blocks.append(self.cleanup_report_cloudwatch_logs_by_last_log_date())

    def cleanup_report_cloudwatch_logs_by_all_log_dates(self):
        current_time = datetime.datetime.now()

        def map_timestamp_to_key(log_timestamp):
            datetime_log_timestamp = datetime.datetime.fromtimestamp(log_timestamp / 1000.0)
            date_log_delta = current_time - datetime_log_timestamp
            return int(date_log_delta.days / 365), datetime_log_timestamp

        stream_size_report = "Stream size"
        total_interval_streams_size = "Total streams size"
        dict_reports = {}

        for log_group in self.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    key_year_last, date_log_timestamp_last = map_timestamp_to_key(log_stream.last_event_timestamp)
                    key_year_first, date_log_timestamp_first = map_timestamp_to_key(log_stream.first_event_timestamp)

                    if key_year_last != 0:
                        continue

                    if key_year_last not in dict_reports:
                        dict_reports[key_year_last] = {}

                    if key_year_first not in dict_reports[key_year_last]:
                        dict_reports[key_year_last][key_year_first] = {}

                    if stream_size_report not in dict_reports[key_year_last][key_year_first]:
                        dict_reports[key_year_last][key_year_first][stream_size_report] = TextBlock(stream_size_report)
                        dict_reports[key_year_last][key_year_first][total_interval_streams_size] = 0

                    dict_reports[key_year_last][key_year_first][total_interval_streams_size] += log_stream.stored_bytes
                    dict_reports[key_year_last][key_year_first][stream_size_report].lines.append("{}-{}: {}: {}: {}".format(date_log_timestamp_last, date_log_timestamp_first, log_group.name, log_stream.name, log_stream.stored_bytes))
                except AttributeError:
                    continue

        report = TextBlock("Cleaning logs by log duration")
        raise NotImplementedError()
        print(report)
        pdb.set_trace()
        return report

    def cleanup_report_cloudwatch_logs_by_last_log_date(self):
        current_time = datetime.datetime.now()

        def map_timestamp_to_key(log_timestamp):
            datetime_log_timestamp = datetime.datetime.fromtimestamp(log_timestamp / 1000.0)
            date_log_delta = current_time - datetime_log_timestamp
            return int(date_log_delta.days/365), datetime_log_timestamp

        empty_streams_report = "Empty streams found"
        stream_size_report = "Stream size report"
        total_streams_size = "Total streams size"
        dict_reports = {}

        for log_group in self.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    key_line, date_log_timestamp = map_timestamp_to_key(log_stream.last_event_timestamp)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if stream_size_report not in dict_reports[key_line]:
                        dict_reports[key_line][stream_size_report] = TextBlock(stream_size_report)
                        dict_reports[key_line][total_streams_size] = 0

                    dict_reports[key_line][total_streams_size] += log_stream.stored_bytes
                    dict_reports[key_line][stream_size_report].lines.append("{}: {}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name, log_stream.stored_bytes))
                except AttributeError:
                    # handle empty log
                    if log_stream.stored_bytes > 0:
                        raise RuntimeError("When no last_event_time exists, sotred_bytes expected to be 0 {}: {}: {}".format(log_group.name, log_stream.name, log_stream.last_event_timestamp))

                    key_line, date_log_timestamp = map_timestamp_to_key(log_stream.creation_time)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if empty_streams_report not in dict_reports[key_line]:
                        dict_reports[key_line][empty_streams_report] = TextBlock(empty_streams_report)

                    dict_reports[key_line][empty_streams_report].lines.append("{}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name))
                    continue

        report = TextBlock("Cleaning logs by last written log line date")
        for year in dict_reports:
            report_year = TextBlock("{} years ago".format(year))

            report_year.lines.append("{}: {} MB".format(total_streams_size, int(dict_reports[year][total_streams_size]/(1024*1024))))
            report_year.lines.append("{}: {}".format(empty_streams_report, len(dict_reports[year][empty_streams_report].lines)))

            report.blocks.append(report_year)

        print(report)
        return report

    def delete_cloudwatch_logs_by_last_event_date(self, date_event_limit=datetime.datetime.now() - datetime.timedelta(days=365)):
        for log_group in self.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    key_line, date_log_timestamp = map_timestamp_to_key(log_stream.last_event_timestamp)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if stream_size_report not in dict_reports[key_line]:
                        dict_reports[key_line][stream_size_report] = TextBlock(stream_size_report)
                        dict_reports[key_line][total_streams_size] = 0

                    dict_reports[key_line][total_streams_size] += log_stream.stored_bytes
                    dict_reports[key_line][stream_size_report].lines.append("{}: {}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name, log_stream.stored_bytes))
                except AttributeError:
                    # handle empty log
                    if log_stream.stored_bytes > 0:
                        raise RuntimeError("When no last_event_time exists, sotred_bytes expected to be 0 {}: {}: {}".format(log_group.name, log_stream.name, log_stream.last_event_timestamp))

                    key_line, date_log_timestamp = map_timestamp_to_key(log_stream.creation_time)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if empty_streams_report not in dict_reports[key_line]:
                        dict_reports[key_line][empty_streams_report] = TextBlock(empty_streams_report)

                    dict_reports[key_line][empty_streams_report].lines.append("{}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name))
                    continue

        report = TextBlock("Cleaning logs by last written log line date")
        for year in dict_reports:
            report_year = TextBlock("{} years ago".format(year))

            report_year.lines.append("{}: {} MB".format(total_streams_size, int(dict_reports[year][total_streams_size]/(1024*1024))))
            report_year.lines.append("{}: {}".format(empty_streams_report, len(dict_reports[year][empty_streams_report].lines)))

            report.blocks.append(report_year)

        print(report)
        return report

    def cleanup_load_balancers(self):
        unuzed_load_balancers = []
        for load_balancer in self.classic_load_balancers:
            if not load_balancer.instances:
                unuzed_load_balancers.append(load_balancer)

        lbs_using_tg = set()
        for target_group in self.target_groups:
            lbs_using_tg.update(target_group.load_balancer_arns)

        unuzed_load_balancers_2 = []
        # = CommonUtils.find_objects_by_values(self.load_balancers, {"arn": lb_arn})
        for load_balancer in self.load_balancers:
            if load_balancer.arn not in lbs_using_tg:
                unuzed_load_balancers_2.append(load_balancer)
        pdb.set_trace()

    def cleanup_target_groups(self):
        lst_ret = []
        for target_group in self.target_groups:
            if not target_group.target_health:
                lst_ret.append(target_group)
                #print("{} - target group has no targets".format(target_group.name))
        return lst_ret

    def cleanup_report_ec2_paths(self):
        sg_map = self.prepare_security_groups_mapping()
        for ec2_instace in self.ec2_instances:
            ret = self.find_ec2_instance_outgoing_paths(ec2_instace, sg_map)

    def find_ec2_instance_outgoing_paths(self, ec2_instace, sg_map):
        for grp in ec2_instace.security_groups:
            paths = sg_map.find_outgoing_paths(grp["GroupId"])
            pdb.set_trace()

    def cleanup_report_security_groups(self):
        sg_map = self.prepare_security_groups_mapping()
        self.ec2_client.connect()
        for sg_id, node in sg_map.nodes.items():
            if len(node.data) == 0:
                sg = CommonUtils.find_objects_by_values(self.security_groups, {"id": sg_id}, max_count=1)
                lst_inter = self.ec2_client.execute(self.ec2_client.client.describe_network_interfaces, "NetworkInterfaces", filters_req={"Filters": [{"Name": "group-id", "Values": [sg_id]}]})
                if lst_inter:
                    pdb.set_trace()
                print("{}:{}:{}".format(sg_id, sg[0].name, lst_inter))

    def prepare_security_groups_mapping(self):
        sg_map = SecurityGroupsMap()
        for sg in self.security_groups:
            node = SecurityGroupMapNode(sg)
            sg_map.add_node(node)

        for ec2_instance in self.ec2_instances:
            for endpoint in ec2_instance.get_security_groups_endpoints():

                sg_map.add_node_data(endpoint["sg_id"], endpoint)

        for lb in self.load_balancers:
            for endpoint in lb.get_security_groups_endpoints():
                sg_map.add_node_data(endpoint["sg_id"], endpoint)

        for rds in self.databases:
            for endpoint in rds.get_security_groups_endpoints():
                sg_map.add_node_data(endpoint["sg_id"], endpoint)

        return sg_map

    def cleanup_report_dns_records(self):
        dns_map = self.prepare_hosted_zones_mapping()
        return ret

    def find_ec2_instances_by_security_group_name(self, name):
        lst_ret = []
        for inst in self.ec2_instances:
            for grp in inst.security_groups:
                if grp["GroupName"] == name:
                    lst_ret.append(inst)
                    break
        return lst_ret

    def get_ec2_instances_h_flow_destinations(self):
        sg_map = self.prepare_security_groups_mapping()
        lst_ret = []
        for ec2_instance in self.ec2_instances:
            for endpoint in ec2_instance.get_security_groups_endpoints():
                print(endpoint)
                hflow = HFlow()
                tunnel = hflow.Tunnel()
                tunnel.traffic_start = HFlow.Tunnel.Traffic()
                tunnel.traffic_end = HFlow.Tunnel.Traffic()

                end_point_src = hflow.EndPoint()
                if "ip" not in endpoint:
                    print("ec2_instance: {} ip not in interface: {}/{}".format(ec2_instance.name, endpoint["device_name"], endpoint["device_id"]))
                    continue
                end_point_src.ip = endpoint["ip"]

                tunnel.traffic_start.ip_src = endpoint["ip"]

                if "dns" in endpoint:
                    #print("ec2_instance: {} dns not in interface: {}/{}".format(ec2_instance.name, endpoint["device_name"], endpoint["device_id"]))
                    end_point_src.dns = endpoint["dns"]
                    tunnel.traffic_start.dns_src = endpoint["dns"]

                end_point_src.add_custom("security_group_id", endpoint["sg_id"])

                hflow.end_point_src = end_point_src

                end_point_dst = hflow.EndPoint()
                hflow.end_point_dst = end_point_dst

                tunnel.traffic_start.ip_dst = tunnel.traffic_start.any()
                hflow.tunnel = tunnel
                lst_flow = sg_map.apply_dst_h_flow_filters(hflow)
                #lst_resources = self.find_resources_by_network(lst_flow[-1])
                lst_ret += lst_flow
                #print("{}: {}".format(len(lst_flow), lst_flow))

                #pdb.set_trace()

        pdb.set_trace()
        return lst_ret
        #print("Total hflows count: {}".format(total_count))
        #self.find_end_point_by_dns()

    def find_resources_by_network(self, ip_addr):
        lst_ret = self.find_ec2_instances_by_ip(ip_addr)
        lst_ret += self.find_loadbalancers_by_network(ip_addr)
        lst_ret += self.find_rdss_by_network(ip_addr)
        #lst_ret += self.find_elastic_searches_by_network(ip_addr)
        return lst_ret

    def find_elastic_searches_by_network(self, ip_addr):
        pdb.set_trace()

        lst_ret = []
        for ec2_instance in self.ec2_instances:
            if any(ip_addr.intersect(inter_ip) is not None for inter_ip in ec2_instance.get_all_addresses()):
                lst_ret.append(ec2_instance)
        return lst_ret

    def find_rdss_by_network(self, ip_addr):
        lst_ret = []
        for obj in self.databases:
            for ip in obj.get_all_networks(self.vpc_subnets):
                if ip_addr.intersect(ip):
                    lst_ret.append(obj)
                    break
        return lst_ret

    def find_loadbalancers_by_network(self, ip_addr):
        """
            find load balancers, having network interscting the src network
            only configs data
            :param ip_addr:
            :return:
            """
        lst_ret = []

        for obj in self.load_balancers + self.classic_load_balancers:
            for ip in obj.get_all_networks(self.vpc_subnets):
                if ip_addr.intersect(ip):
                    lst_ret.append(obj)
                    break

        return lst_ret

    def find_loadbalancers_by_ip(self, ip_addr):
        """
        find load balancer by ip- resolve dns to ip and check intersects
        live data/cache data
        :param ip_addr:
        :return:
        """
        raise NotImplementedError
        lst_ret = []

        for obj in self.load_balancers + self.classic_load_balancers:
            for vpc_subnet in obj.get_all_networks(self.vpc_subnets):
                if isinstance(addr, IP):
                    lst_addr = [addr]
                elif isinstance(addr, DNS):
                    pdb.set_trace()
                    lst_addr = AWSAPI.find_ips_from_dns(addr)
                else:
                    raise ValueError

                for lb_ip_addr in lst_addr:
                    if ip_addr.intersect(lb_ip_addr):
                        lst_ret.append(obj)
                        break
                else:
                    continue

                break

        return lst_ret

    def find_ec2_instances_by_ip(self, ip_addr):
        lst_ret = []
        for ec2_instance in self.ec2_instances:
            if any(ip_addr.intersect(inter_ip) is not None for inter_ip in ec2_instance.get_all_addresses()):
                lst_ret.append(ec2_instance)
        return lst_ret

    @staticmethod
    def cache_dns_addresses(dns, ips):
        print("Todo: Cache ips {}".format(dns.fqdn))

    @staticmethod
    def find_ips_from_dns(dns):
        try:
            addr_info_lst = socket.getaddrinfo(dns.fqdn, None)
            addresses = [pair[4][0] for pair in addr_info_lst]
            addresses = set(addresses)
            addresses = [IP("{}/32".format(address)) for address in addresses]
            AWSAPI.cache_dns_addresses(dns, addresses)
            return addresses
        except socket.gaierror as e:
            #raise Exception("Can't find address from socket")
            #pdb.set_trace()

            print("todo: init address from dns: {}".format(dns))
            ip = IP("1.1.1.1/32")
            return [ip]

        raise Exception

        addresses = {addr_info[4][0] for addr_info in addr_info_lst}
        addresses = {IP(address, int_mask=32) for address in addresses}

        if len(addresses) != 1:
            pdb.set_trace()
            raise NotImplementedError

        for address in addresses:
            endpoint["ip"] = address


        print("todo: init address from dns: {}".format(dns))
        ip = IP("1.1.1.1")
        return ip
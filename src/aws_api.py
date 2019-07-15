import json
import pdb
import os
import sys

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))
from enum import Enum
from ip import IP

from ec2_client import EC2Client
from ec2_instance import EC2Instance
from ec2_security_group import EC2SecurityGroup

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


class HFlow(object):
    def __init__(self):
        self.tunnels = []
        self.source = None
        self.sink = None

    class EndPoint(object):
        def __init__(self):
            self.type = None
            # can be "flow end" (if the flow reached its destination)
            # can be "internet"
            self.data = None  # dict {"type":"ec2", "value":obj}


class HTunnel(object):
    def __init__(self):
        pass


class IPTunnel(HTunnel):
    def __init__(self):
        super(IPTunnel, self).__init__()
        self.src = None
        self.dst = None


class TextBlock(object):
    def __init__(self, header):
        self.header = header
        self.lines = []
        self.blocks = []
        self.footer = []


class DNS(object):
    def __init__(self):
        self.fqdn = None


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
            # {'Name': 'srv.alerts.local.env.fbx.im.', 'Type': 'SRV', 'TTL': 1, 'ResourceRecords': [{'Value': '1 10 10080 alerts.local.env.fbx.im'}]}
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

        for permission in self.security_group.ip_permissions:
            self.add_edges_from_permission(self.incoming_edges, permission)

        for permission in self.security_group.ip_permissions_egress:
            self.add_edges_from_permission(self.outgoing_edges, permission)

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

            edge = SecurityGroupMapEdge(edge_type, value, description, ip_protocol, from_port, to_port)
            dst_lst.append(edge)

        if permission.prefix_list_ids:
            raise Exception

    def add_data(self, data):
        pdb.set_trace()


class SecurityGroupsMap(object):
    def __init__(self):
        self.nodes = {}

    def add_node(self, node):
        if node.security_group.id in self.nodes:
            raise Exception

        self.nodes[node.security_group.id] = node

    def add_node_data(self, security_group_id, data):
        self.nodes[security_group_id].add_data(data)


class AWSAPI(object):

    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        self.aws_key_id = aws_key_id
        self.aws_access_secret = aws_access_secret
        self.iam_client = IamClient(aws_key_id, aws_access_secret, region_name, logger)
        self.ec2_client = EC2Client(aws_key_id, aws_access_secret, region_name, logger)
        self.s3_client = S3Client(aws_key_id, aws_access_secret, region_name, logger)
        self.elbv2_client = ELBV2Client(aws_key_id, aws_access_secret, region_name, logger)
        self.elb_client = ELBClient(aws_key_id, aws_access_secret, region_name, logger)
        self.rds_client = RDSClient(aws_key_id, aws_access_secret, region_name, logger)
        self.route53_client = Route53Client(aws_key_id, aws_access_secret, region_name, logger)
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
            fil.write(json.dumps(objects_dicts))

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
        ret = self.cleanup_report_security_groups()
        ret = self.cleanup_report_dns_records()
        return ret

    def cleanup_report_security_groups(self):
        sg_map = self.prepare_security_groups_mapping()

    def prepare_security_groups_mapping(self):
        sg_map = SecurityGroupsMap()
        for sg in self.security_groups:
            node = SecurityGroupMapNode(sg)
            sg_map.add_node(node)

        for ec2_instance in self.ec2_instances:
            sg_ids = ec2_instance.get_security_groups_endpoints()
            for sg_id in sg_ids:
                sg_map.add_node_data(sg_id, ec2_instance)

        for lb in self.load_balancers:
            sg_ids = lb.get_security_groups_endpoints()
            for sg_id in sg_ids:
                continue
                sg_map.add_node_data(sg_id, lb)

        for rds in self.databases:
            endpoints = rds.get_security_groups_endpoints()
            for endpoint in endpoints:
                sg_map.add_node_data(endpoint["sg_id"], endpoint)

        pdb.set_trace()


    def cleanup_report_dns_records(self):
        dns_map = self.prepare_hosted_zones_mapping()
        return ret

    def h_flow_calc(self):
        dns_map = self.prepare_hosted_zones_mapping()

        hflow = HFlow()
        tunnel = IPTunnel()
        tunnel.src = IP()
        tunnel.dst = DNS()
        tunnel.dst
        hflow.tunnels.append(tunnel)

        pdb.set_trace()
        self.find_end_point_by_dns()

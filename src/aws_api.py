import json
import pdb
import os
import socket

import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "base_entities")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "aws_services_entities")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "aws_clients")))


from ip import IP

from boto3_client import Boto3Client

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

from lambda_client import LambdaClient
from aws_lambda import AWSLambda

from route53_client import Route53Client
from route53_hosted_zone import HostedZone

from rds_client import RDSClient
from rds_db_instance import DBInstance

from iam_client import IamClient
from iam_policy import IamPolicy
from iam_user import IamUser
from iam_role import IamRole

from common_utils import CommonUtils
from dns import DNS

import datetime
from environment import Environment
from text_block import TextBlock


class AWSAPI(object):
    def __init__(self):
        self.ec2_client = EC2Client()
        self.lambda_client = LambdaClient()
        self.iam_client = IamClient()
        self.s3_client = S3Client()
        self.elbv2_client = ELBV2Client()
        self.elb_client = ELBClient()
        self.rds_client = RDSClient()
        self.route53_client = Route53Client()

        self.iam_policies = []
        self.ec2_instances = []
        self.s3_buckets = []
        self.load_balancers = []
        self.classic_load_balancers = []
        self.hosted_zones = []
        self.users = []
        self.databases = []
        self.security_groups = []
        self.target_groups = []
        self.lambdas = []
        self.iam_roles = []

    def init_ec2_instances(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, EC2Instance)
        else:
            objects = self.ec2_client.get_all_instances()

        self.ec2_instances += objects

    def init_users(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, IamUser)
        else:
            objects = self.iam_client.get_all_users()

        self.users = objects

    def init_iam_roles(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, IamRole)
        else:
            objects = self.iam_client.get_all_roles(policies=self.iam_policies)

        self.iam_roles += objects

    def init_iam_policies(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, IamPolicy)
        else:
            objects = self.iam_client.get_all_policies()

        self.iam_policies = objects

    def init_s3_buckets(self, from_cache=False, cache_file=None, full_information=True):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, S3Bucket)
        else:
            objects = self.s3_client.get_all_buckets(full_information=full_information)

        self.s3_buckets = objects

    def init_and_cache_s3_bucket_objects(self, buckets_objects_cache_dir):
        for bucket in self.s3_buckets:
            bucket_dir = os.path.join(buckets_objects_cache_dir, bucket.name)

            # todo: maybe remove?
            if os.path.exists(bucket_dir):
                continue

            print(bucket.name)
            bucket_objects = []
            bucket_objects = list(self.s3_client.yield_bucket_objects(bucket))
            len_bucket_objects = len(bucket_objects)

            os.makedirs(bucket_dir, exist_ok=True)

            if len_bucket_objects == 0:
                continue

            max_count = 100000

            for i in range(int(len_bucket_objects/max_count) + 1):
                first_key_index = max_count * i
                last_key_index = (min(max_count * (i+1), len_bucket_objects)) - 1
                file_name = bucket_objects[last_key_index].key.replace("/", "_")
                file_path = os.path.join(bucket_dir, file_name)

                #todo: maybe remove?
                if os.path.exists(file_path):
                    continue

                data_to_dump = [obj.convert_to_dict() for obj in bucket_objects[first_key_index: last_key_index]]

                with open(file_path, "w") as fd:
                    json.dump(data_to_dump, fd)

            print(f"{bucket.name}: {len(bucket_objects)}")

    def init_lambdas(self, from_cache=False, cache_file=None, full_information=True):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, AWSLambda)
        else:
            objects = self.lambda_client.get_all_lambdas(full_information=full_information)

        self.lambdas += objects

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

    def set_environment(self, env):
        self._environment = env

    def unset_environment(self):
        self._environment = None

    @staticmethod
    def start_assuming_role(role_arn):
        Boto3Client.start_assuming_role(role_arn)

    @staticmethod
    def stop_assuming_role():
        Boto3Client.stop_assuming_role()

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
        # todo: check roles policies overlapping - if a policy regex includes other policies regex string
        ret = self.cleanup_load_balancers()
        ret = self.cleanup_target_groups()
        pdb.set_trace()
        ret = self.cleanup_report_ec2_paths()
        pdb.set_trace()
        ret = self.cleanup_report_security_groups()
        ret = self.cleanup_report_dns_records()

        return ret

    def cleanup_report_lambdas_large_lambdas(self):
        tb_ret = TextBlock("Large lambdas")
        limit = 100 * 1024 * 1024
        for aws_lambda in self.lambdas:
            if aws_lambda.code_size >= limit:
                line = f"{aws_lambda.name}: {aws_lambda.code_size} > 100MB"
                tb_ret.lines.append(line)
        return tb_ret

    def cleanup_report_lambdas_old_code(self):
        tb_ret = TextBlock("Large lambdas")
        year_ago = datetime.datetime.now() - datetime.timedelta(days=365)
        for aws_lambda in self.lambdas:
            pdb.set_trace()
            if aws_lambda.last_modified < year_ago:
                line = f"{aws_lambda.name}: {aws_lambda.last_modified} was more than a year ago"
                tb_ret.lines.append(line)
        pdb.set_trace()
        return tb_ret

    def cleanup_report_lambdas(self):
        tb_ret = TextBlock("Lambdas cleanup")
        tb_ret.blocks.append(self.cleanup_report_lambdas_large_lambdas())
        tb_ret.blocks.append(self.cleanup_report_lambdas_old_code())
        return tb_ret

    def cleanup_report_s3_buckets(self):
        tb_ret = TextBlock("All buckets' keys")
        for bucket in self.s3_buckets:
            print(bucket.name)
            bucket_objects = list(self.s3_client.yield_bucket_objects(bucket))

            print(f"{bucket.name}: {len(bucket_objects)}")
            tb_ret.lines.append(f"{bucket.name}: {len(bucket_objects)}")

        pdb.set_trace()
        return tb_ret

    def account_id_from_arn(self, arn):
        if isinstance(arn, list):
            print(arn)
            pdb.set_trace()
        if not arn.startswith("arn:aws:iam::"):
            raise ValueError(arn)

        account_id = arn[len("arn:aws:iam::"):]
        account_id = account_id[:account_id.find(":")]
        if not account_id.isdigit():
            raise ValueError(arn)
        return account_id

    def cleanup_report_iam_roles(self):
        """
        1) Last activity

        :return:
        """
        tb_ret = TextBlock("Iam Roles")
        known_services = []
        for iam_role in self.iam_roles:
            role_account_id = self.account_id_from_arn(iam_role.arn)
            doc = iam_role.assume_role_policy_document
            for statement in doc["Statement"]:
                if statement["Action"] == "sts:AssumeRole":
                    if statement["Effect"] != "Allow":
                        raise ValueError(statement["Effect"])
                    if "Service" in statement["Principal"]:
                        pass
                        if isinstance(statement["Principal"]["Service"], list):
                            for service_name in statement["Principal"]["Service"]:
                                known_services.append(service_name)
                        else:
                            known_services.append(statement["Principal"]["Service"])
                        #pdb.set_trace()
                        #continue
                    elif "AWS" in statement["Principal"]:
                        principal_arn = statement["Principal"]["AWS"]
                        principal_account_id = self.account_id_from_arn(principal_arn)
                        if principal_account_id != role_account_id:
                            print(statement)
                elif statement["Action"] == "sts:AssumeRoleWithSAML":
                    pass
                elif statement["Action"] == "sts:AssumeRoleWithWebIdentity":
                    pass
                else:
                    print(f"{iam_role.name}: {statement['Action']}")
            #tb_ret.lines.append(f"{bucket.name}: {len(bucket_objects)}")
        ret = set(known_services)
        pdb.set_trace()
        return tb_ret

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
        total_count = 0
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
                    end_point_src.dns = DNS(endpoint["dns"])
                    tunnel.traffic_start.dns_src = DNS(endpoint["dns"])

                end_point_src.add_custom("security_group_id", endpoint["sg_id"])

                hflow.end_point_src = end_point_src

                end_point_dst = hflow.EndPoint()
                hflow.end_point_dst = end_point_dst

                tunnel.traffic_start.ip_dst = tunnel.traffic_start.any()
                hflow.tunnel = tunnel
                lst_flow = sg_map.apply_dst_h_flow_filters_multihop(hflow)
                lst_resources = self.find_resources_by_ip(lst_flow[-1])
                pdb.set_trace()
                total_count += 1
                print("{}: {}".format(len(lst_flow), lst_flow))

                #pdb.set_trace()

        print("Total hflows count: {}".format(total_count))
        pdb.set_trace()
        self.find_end_point_by_dns()

    def find_resources_by_ip(self, ip_addr):
        lst_ret = self.find_ec2_instances_by_ip(ip_addr)
        lst_ret += self.find_loadbalancers_by_ip(ip_addr)
        lst_ret += self.find_rdss_by_ip(ip_addr)
        lst_ret += self.find_elastic_searches_by_ip(ip_addr)
        return lst_ret

    def find_elastic_searches_by_ip(self, ip_addr):
        raise NotImplementedError
        lst_ret = []
        for ec2_instance in self.ec2_instances:
            if any(ip_addr.intersect(inter_ip) is not None for inter_ip in ec2_instance.get_all_ips()):
                lst_ret.append(ec2_instance)
        return lst_ret

    def find_rdss_by_ip(self, ip_addr):
        raise NotImplementedError
        lst_ret = []
        for ec2_instance in self.ec2_instances:
            if any(ip_addr.intersect(inter_ip) is not None for inter_ip in ec2_instance.get_all_ips()):
                lst_ret.append(ec2_instance)
        return lst_ret

    def find_loadbalancers_by_ip(self, ip_addr):
        lst_ret = []

        for obj in self.load_balancers + self.classic_load_balancers:
            for addr in obj.get_all_addresses():
                if isinstance(addr, IP):
                    lst_addr = [addr]
                elif isinstance(addr, DNS):
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
            if any(ip_addr.intersect(inter_ip) is not None for inter_ip in ec2_instance.get_all_ips()):
                lst_ret.append(ec2_instance)
        return lst_ret

    @staticmethod
    def find_ips_from_dns(dns):
        print("todo: init address from dns: {}".format(dns))
        ip = IP("1.1.1.1/32")
        return [ip]

        try:
            addr_info_lst = socket.getaddrinfo(dns, None)
        except socket.gaierror as e:
            raise Exception("Can't find address from socket")

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
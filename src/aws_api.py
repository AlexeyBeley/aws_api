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

from cloud_watch_logs_client import CloudWatchLogsClient
from cloud_watch_log_group import CloudWatchLogGroup

from common_utils import CommonUtils
from dns import DNS

import datetime
from environment import Environment
from text_block import TextBlock
from h_logger import get_logger

from collections import defaultdict
from dns_map import DNSMap

logger = get_logger()

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
        self.cloud_watch_logs_client = CloudWatchLogsClient()

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
        self.cloud_watch_log_groups = []

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

    def init_cloud_watch_log_groups(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, CloudWatchLogGroup)
        else:
            objects = self.cloud_watch_logs_client.get_cloud_watch_log_groups()

        self.cloud_watch_log_groups = objects

    def init_and_cache_raw_large_cloud_watch_log_groups(self, cache_dir):
        os.makedirs(cache_dir, exist_ok=True)
        log_groups = self.cloud_watch_logs_client.get_cloud_watch_log_groups(full_information=False)
        for log_group in log_groups:
            sub_dir = os.path.join(cache_dir, log_group.name.lower().replace("/", "_"))
            os.makedirs(sub_dir, exist_ok=True)
            logger.info(f"Starting collecting from bucket: {sub_dir}")

            stream_generator = self.cloud_watch_logs_client.yield_log_group_streams(log_group.name)
            self.cache_large_objects_from_generator(stream_generator, sub_dir)

    def cache_large_objects_from_generator(self, generator, sub_dir):
        total_counter = 0
        counter = 0
        max_count = 100
        buffer = []

        for dict_src in generator:
            counter += 1
            total_counter += 1
            buffer.append(dict_src)

            if counter < max_count:
                continue
            logger.info(f"Objects total_counter: {total_counter}")
            logger.info(f"Writing chunk of {max_count} to file {sub_dir}")

            file_path = os.path.join(sub_dir, str(total_counter))

            with open(file_path, "w") as fd:
                json.dump(buffer, fd)

            counter = 0
            buffer = []

        logger.info(f"Dir {sub_dir} total count of objects: {total_counter}")

        if total_counter == 0:
            return

        file_path = os.path.join(sub_dir, str(total_counter))

        with open(file_path, "w") as fd:
            json.dump(buffer, fd)

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

    def init_and_cache_s3_bucket_objects_synchronous(self, buckets_objects_cache_dir):
        max_count = 100000
        for bucket in self.s3_buckets:
            bucket_dir = os.path.join(buckets_objects_cache_dir, bucket.name)

            # todo: maybe remove?
            if os.path.exists(bucket_dir):
                continue

            print(bucket.name)
            pdb.set_trace()
            bucket_objects = list(self.s3_client.yield_bucket_objects(bucket))
            len_bucket_objects = len(bucket_objects)

            os.makedirs(bucket_dir, exist_ok=True)

            if len_bucket_objects == 0:
                continue

            for i in range(int(len_bucket_objects/max_count) + 1):
                first_key_index = max_count * i
                last_key_index = (min(max_count * (i+1), len_bucket_objects)) - 1
                file_name = bucket_objects[last_key_index].key.replace("/", "_")
                file_path = os.path.join(bucket_dir, file_name)

                data_to_dump = [obj.convert_to_dict() for obj in bucket_objects[first_key_index: last_key_index]]

                with open(file_path, "w") as fd:
                    json.dump(data_to_dump, fd)

            print(f"{bucket.name}: {len(bucket_objects)}")

    def init_and_cache_s3_bucket_objects(self, buckets_objects_cache_dir, bucket_name=None):
        """
        each bucket object represented as 388.586973867 B string in file
        :param buckets_objects_cache_dir:
        :param bucket_name:
        :return:
        """
        max_count = 100000
        for bucket in self.s3_buckets:
            if bucket_name is not None and bucket.name != bucket_name:
                continue

            bucket_dir = os.path.join(buckets_objects_cache_dir, bucket.name)
            os.makedirs(bucket_dir, exist_ok=True)
            logger.info(f"Starting collecting from bucket: {bucket.name}")

            bucket_objects_iterator = self.s3_client.yield_bucket_objects(bucket)
            total_counter = 0
            counter = 0

            buffer = []
            for bucket_object in bucket_objects_iterator:
                counter += 1
                total_counter += 1
                buffer.append(bucket_object)

                if counter < max_count:
                    continue
                logger.info(f"Bucket objects total_counter: {total_counter}")
                logger.info(f"Writing chunk of {max_count} objects for bucket {bucket.name}")
                counter = 0
                file_name = bucket_object.key.replace("/", "_")
                file_path = os.path.join(bucket_dir, file_name)

                data_to_dump = [obj.convert_to_dict() for obj in buffer]

                buffer = []

                with open(file_path, "w") as fd:
                    json.dump(data_to_dump, fd)

            logger.info(f"Bucket {bucket.name} total count of objects: {total_counter}")

            if total_counter == 0:
                continue

            file_name = bucket_object.key.replace("/", "_")
            file_path = os.path.join(bucket_dir, file_name)

            data_to_dump = [obj.convert_to_dict() for obj in buffer]

            with open(file_path, "w") as fd:
                json.dump(data_to_dump, fd)

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

        self.load_balancers += objects

    def init_classic_load_balancers(self, from_cache=False, cache_file=None):
        if from_cache:
            objects = self.load_objects_from_cache(cache_file, ClassicLoadBalancer)
        else:
            objects = self.elb_client.get_all_load_balancers()

        self.classic_load_balancers += objects

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
        pdb.set_trace()
        self.security_groups += objects

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

    def get_down_instances(self):
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

    def cleanup_report_s3_buckets_objects(self, summarised_data_file):
        with open(summarised_data_file) as fh:
            all_buckets = json.load(fh)

        by_bucket_sorted_data = dict()

        for bucket_name, bucket_data in all_buckets.items():
            by_bucket_sorted_data[bucket_name] = {"total_size": 0, "total_keys": 0, "years": {}}
            logger.info(f"Init bucket '{bucket_name}'")

            for year, year_data in sorted(bucket_data.items(), key=lambda x: x[0]):
                year_dict = {"total_size": 0, "total_keys": 0, "months": {}}
                by_bucket_sorted_data[bucket_name]["years"][year] = year_dict

                for month, month_data in sorted(year_data.items(), key=lambda x: int(x[0])):
                    year_dict["months"][month] = {"total_size": 0, "total_keys": 0}
                    for day, day_data in month_data.items():
                        year_dict["months"][month]["total_size"] += day_data["size"]
                        year_dict["months"][month]["total_keys"] += day_data["keys"]
                    year_dict["total_size"] += year_dict["months"][month]["total_size"]
                    year_dict["total_keys"] += year_dict["months"][month]["total_keys"]

                by_bucket_sorted_data[bucket_name]["total_size"] += year_dict["total_size"]
                by_bucket_sorted_data[bucket_name]["total_keys"] += year_dict["total_keys"]

        tb_ret = TextBlock("Buckets sizes report per years")
        for bucket_name, bucket_data in sorted(by_bucket_sorted_data.items(), reverse=True, key=lambda x: x[1]["total_size"]):
            tb_bucket = TextBlock(f"Bucket_Name: '{bucket_name}' size: {CommonUtils.bytes_to_str(bucket_data['total_size'])}, keys: {CommonUtils.int_to_str(bucket_data['total_keys'])}")

            for year, year_data in bucket_data["years"].items():
                tb_year = TextBlock(
                        f"{year} size: {CommonUtils.bytes_to_str(year_data['total_size'])}, keys: {CommonUtils.int_to_str(year_data['total_keys'])}")

                for month, month_data in year_data["months"].items():
                    line = f"{month} size: {CommonUtils.bytes_to_str(month_data['total_size'])}, keys: {CommonUtils.int_to_str(month_data['total_keys'])}"
                    tb_year.lines.append(line)

                tb_bucket.blocks.append(tb_year)

            tb_ret.blocks.append(tb_bucket)

        print(tb_ret.format_pprint())
        with open("./tmp_output.txt", "w") as fh:
            fh.write(tb_ret.format_pprint())

        return tb_ret

    def generate_summarised_s3_cleanup_data(self, buckets_dir_path, summarised_data_file):
        all_buckets = dict()
        for bucket_dir in os.listdir(buckets_dir_path):
            by_date_split = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {"keys": 0, "size": 0})))
            logger.info(f"Init bucket in dir '{bucket_dir}'")

            bucket_dir_path = os.path.join(buckets_dir_path, bucket_dir)
            for objects_buffer_file in os.listdir(bucket_dir_path):
                logger.info(f"Init objects chunk in dir {bucket_dir}/{objects_buffer_file}")
                objects_buffer_file_path = os.path.join(bucket_dir_path, objects_buffer_file)

                with open(objects_buffer_file_path) as fh:
                    lst_objects = json.load(fh)

                for dict_object in lst_objects:
                    bucket_object = S3Bucket.BucketObject(dict_object, from_cache=True)
                    by_date_split[bucket_object.last_modified.year][bucket_object.last_modified.month][bucket_object.last_modified.day]["keys"] += 1
                    by_date_split[bucket_object.last_modified.year][bucket_object.last_modified.month][bucket_object.last_modified.day]["size"] += bucket_object.size
            all_buckets[bucket_dir] = by_date_split
        with open(summarised_data_file, "w") as fh:
            json.dump(all_buckets, fh)

    def cleanup_report_s3_buckets_objects_large(self, all_buckets):
        tb_ret = TextBlock(header="Large buckets")
        lst_buckets_total = []
        for bucket_name, by_year_split in all_buckets:
            bucket_total = sum([per_year_data["size"] for per_year_data in by_year_split.values()])
            lst_buckets_total.append((bucket_name, bucket_total))

        lst_buckets_total_sorted = sorted(lst_buckets_total, reverse=True, key=lambda x: x[1])
        for name, size in lst_buckets_total_sorted[:20]:
            tb_ret.lines.append(f"{name}: {CommonUtils.bytes_to_str(size)}")
        #pdb.set_trace()
        return tb_ret


    def cleanup_report_s3_buckets(self):
        raise NotImplementedError()
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

    def cleanup_report_iam_policy_statements_optimize_not_statement(self, statement):
        """
        https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html
        :param statement:
        :return:
        """
        lines = []

        if statement.effect == statement.Effects.ALLOW:
            if statement.not_action != {}:
                lines.append(f"Potential risk in too permissive not_action. Effect: 'Allow', not_action: '{statement.not_action}'")
            if statement.not_resource is not None:
                lines.append(f"Potential risk in too permissive not_resource. Effect: 'Allow', not_resource: '{statement.not_resource}'")
        return lines

    def cleanup_report_iam_policy_statements_intersecting_statements(self, statements):
        lines = []
        for i in range(len(statements)):
            statement_1 = statements[i]
            for j in range(i+1, len(statements)):
                statement_2 = statements[j]
                try:
                    statement_1.condition
                    continue
                except Exception:
                    pass

                try:
                    statement_2.condition
                    continue
                except Exception:
                    pass

                common_resource = statement_1.intersect_resource(statement_2)

                if len(common_resource) == 0:
                    continue
                common_action = statement_1.intersect_action(statement_2)

                if len(common_action) == 0:
                    continue
                lines.append(f"Common Action: {common_action} Common resource {common_resource}")
                lines.append(str(statement_1.dict_src))
                lines.append(str(statement_2.dict_src))

        return lines

    def cleanup_report_iam_policy_statements_optimize(self, policy):
        """
        1) action is not of the resource - solved by AWS in creation process.
        2) resource has no action
        3) effect allow + NotResources
        4) resource arn without existing resource
        5) Resources completely included into other resource
        :param policy:
        :return:
        """

        tb_ret = TextBlock(f"Policy_Name: {policy.name}")
        for statement in policy.document.statements:
            lines = self.cleanup_report_iam_policy_statements_optimize_not_statement(statement)
            if len(lines) > 0:
                tb_ret.lines += lines
        lines = self.cleanup_report_iam_policy_statements_intersecting_statements(policy.document.statements)
        tb_ret.lines += lines
        return tb_ret

    def cleanup_report_iam_policies_statements_optimize(self):
        tb_ret = TextBlock("Iam Policies optimize statements")
        for policy in self.iam_policies:
            logger.info(f"Optimizing policy {policy.name}")
            tb_policy = self.cleanup_report_iam_policy_statements_optimize(policy)
            if tb_policy.blocks or tb_policy.lines:
                tb_ret.blocks.append(tb_policy)
                #pdb.set_trace()

        print(tb_ret.format_pprint())
        return tb_ret

    @staticmethod
    def enter_n_sorted(items, get_item_weight, item_to_insert):
        item_to_insert_weight = get_item_weight(item_to_insert)

        if len(items) == 0:
            raise ValueError("Not inited items (len=0)")

        for i in range(len(items)):
            if item_to_insert_weight < get_item_weight(items[i]):
                logger.info(f"Found new item to insert with wait {item_to_insert_weight} at place {i} where current weight is {get_item_weight(items[i])}")
                break

        i -= 1

        while i > -1:
            logger.info(f"Updatig item at place {i}")
            item_to_insert_tmp = items[i]
            items[i] = item_to_insert
            item_to_insert = item_to_insert_tmp
            i -= 1

    def cleanup_report_cloud_watch_log_groups_handle_sorted_streams(self, top_streams_count, dict_log_group, stream):
        if top_streams_count < 0:
            return

        if dict_log_group["streams_count"] < top_streams_count:
            dict_log_group["data"]["streams_by_size"].append(stream)
            dict_log_group["data"]["streams_by_date"].append(stream)
            return

        if dict_log_group["streams_count"] == top_streams_count:
            dict_log_group["data"]["streams_by_size"] = sorted(dict_log_group["data"]["streams_by_size"],
                                                               key=lambda x: x["storedBytes"])
            dict_log_group["data"]["streams_by_date"] = sorted(dict_log_group["data"]["streams_by_date"],
                                                               key=lambda x: -(
                                                               x["lastIngestionTime"] if "lastIngestionTime" in x else
                                                               x["creationTime"]))
            return

        self.enter_n_sorted(dict_log_group["data"]["streams_by_size"], lambda x: x["storedBytes"], stream)
        self.enter_n_sorted(dict_log_group["data"]["streams_by_date"],
                        lambda x: -(x["lastIngestionTime"] if "lastIngestionTime" in x else x["creationTime"]), stream)

    @staticmethod
    def cleanup_report_cloud_watch_log_groups_prepare_tb(dict_total, top_streams_count):
        tb_ret = TextBlock("Cloudwatch Logs and Streams")
        line = f"size: {CommonUtils.bytes_to_str(dict_total['size'])} streams: {CommonUtils.int_to_str(dict_total['streams_count'])}"
        tb_ret.lines.append(line)

        for dict_log_group in dict_total["data"]:
            tb_log_group = TextBlock(
                f"{dict_log_group['name']} size: {CommonUtils.bytes_to_str(dict_log_group['size'])}, streams: {CommonUtils.int_to_str(dict_log_group['streams_count'])}")

            lines = []
            total_size = 0
            for stream in dict_log_group["data"]["streams_by_size"]:
                name = stream["logStreamName"]
                size = stream["storedBytes"]
                total_size += size
                last_accessed = stream["lastIngestionTime"] if "lastIngestionTime" in stream else stream["creationTime"]
                last_accessed = CommonUtils.timestamp_to_datetime(last_accessed / 1000.0)
                lines.append(f"{name} size: {CommonUtils.bytes_to_str(size)}, last_accessed: {last_accessed}")

            tb_streams_by_size = TextBlock(
                f"{top_streams_count} largest streams' total size: {CommonUtils.bytes_to_str(total_size)}")
            tb_streams_by_size.lines = lines
            tb_log_group.blocks.append(tb_streams_by_size)

            if dict_log_group['streams_count'] > top_streams_count:
                lines = []
                total_size = 0
                for stream in dict_log_group["data"]["streams_by_date"]:
                    name = stream["logStreamName"]
                    size = stream["storedBytes"]
                    total_size += size
                    last_accessed = stream["lastIngestionTime"] if "lastIngestionTime" in stream else stream["creationTime"]
                    last_accessed = CommonUtils.timestamp_to_datetime(last_accessed / 1000.0)
                    lines.append(f"{name} size: {CommonUtils.bytes_to_str(size)}, last_accessed: {last_accessed}")

                tb_streams_by_date = TextBlock(
                    f"{top_streams_count} ancient streams' total size: {CommonUtils.bytes_to_str(total_size)}")
                tb_streams_by_date.lines = lines
                tb_log_group.blocks.append(tb_streams_by_date)

            tb_ret.blocks.append(tb_log_group)
        return tb_ret

    def cleanup_report_cloud_watch_log_groups(self, streams_dir, top_streams_count=100):
        dict_total = {"size": 0, "streams_count": 0, "data": []}
        for log_group_subdir in os.listdir(streams_dir):
            dict_log_group = {"name": log_group_subdir, "size": 0, "streams_count": 0, "data": {"streams_by_size": [], "streams_by_date": []}}
            log_group_full_path = os.path.join(streams_dir, log_group_subdir)

            for chunk_file in os.listdir(log_group_full_path):
                with open(os.path.join(log_group_full_path, chunk_file)) as fh:
                    streams = json.load(fh)
                for stream in streams:
                    dict_log_group["size"] += stream["storedBytes"]
                    dict_log_group["streams_count"] += 1
                    self.cleanup_report_cloud_watch_log_groups_handle_sorted_streams(top_streams_count, dict_log_group, stream)

            dict_total["size"] += dict_log_group["size"]
            dict_total["streams_count"] += dict_log_group["streams_count"]
            dict_total["data"].append(dict_log_group)
        dict_total["data"] = sorted(dict_total["data"], key=lambda x: x["size"], reverse=True)
        tb_ret = self.cleanup_report_cloud_watch_log_groups_prepare_tb(dict_total, top_streams_count)
        print(tb_ret.format_pprint())
        pdb.set_trace()
        return

    def cleanup_report_iam_policies(self):
        tb_ret = TextBlock("Iam Policies")
        tb_ret.blocks.append(self.cleanup_report_iam_policies_statements_optimize())
        return tb_ret

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
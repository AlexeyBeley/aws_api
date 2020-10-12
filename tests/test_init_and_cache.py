import os
import sys
import pdb

sys.path.insert(0, os.path.abspath("../src"))
sys.path.insert(0, "/Users/alexeybe/private/IP/ip")
sys.path.insert(0, "~/private/aws_api/ignore")
sys.path.insert(0, "~/private/aws_api/src/base_entities")

from aws_api import AWSAPI
import ignore_me
import logging
logger = logging.Logger(__name__)
from aws_account import AWSAccount

# Set account here:
tested_account = ignore_me.acc_rnd
AWSAccount.set_aws_account(tested_account)

aws_api = AWSAPI()

cache_base_path = os.path.join(os.path.expanduser("~"), f"private/aws_api/ignore/cache_objects_{tested_account.name}")
s3_buckets_cache_file = os.path.join(cache_base_path, "s3_buckets.json")
ec2_instances_cache_file = os.path.join(cache_base_path, "ec2_instances.json")
s3_objects_dir = os.path.join(cache_base_path, "s3_buckets_objects")
cloudwatch_log_groups_dir = os.path.join(cache_base_path, "cloudwatch_log_groups")

def test_init_and_cache_ec2instances():
    aws_api.init_ec2_instances()
    aws_api.cache_objects(aws_api.ec2_instances, ec2_instances_cache_file)
    print(f"len(instances) = {len(aws_api.ec2_instances)}")
    assert isinstance(aws_api.ec2_instances, list)


def test_init_and_cache_s3_buckets():
    aws_api.init_s3_buckets()
    aws_api.cache_objects(aws_api.s3_buckets, s3_buckets_cache_file)
    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_s3_bucket_objects():
    aws_api.init_s3_buckets(from_cache=True,
                            cache_file=s3_buckets_cache_file)

    aws_api.init_and_cache_s3_bucket_objects(s3_objects_dir)

    pdb.set_trace()

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_raw_large_cloud_watch_log_groups():
    aws_api.init_and_cache_raw_large_cloud_watch_log_groups(cloudwatch_log_groups_dir)
    print(f"len(cloud_watch_log_groups) = {len(aws_api.cloud_watch_log_groups)}")
    assert isinstance(aws_api.cloud_watch_log_groups, list)


def test_init_and_cache_lambdas():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_lambdas()

    aws_api.cache_objects(aws_api.lambdas, "/Users/alexeybe/private/aws_api/ignore/cache_objects/lambdas.json")

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_iam_roles():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_iam_policies(from_cache=True, cache_file="/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_policies.json")
        aws_api.init_iam_roles()
        aws_api.cache_objects(aws_api.iam_roles, "/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_roles.json")
        pdb.set_trace()
        break

    print(f"len(iam_roles) = {len(aws_api.iam_roles)}")
    assert isinstance(aws_api.iam_roles, list)


def test_init_and_cache_iam_policies():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_iam_policies()
        aws_api.cache_objects(aws_api.iam_policies, "/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_policies.json")
        break

    print(f"len(iam_policies) = {len(aws_api.iam_policies)}")
    assert isinstance(aws_api.iam_policies, list)

cloud_watch_cache = "cache/cloud_watch_log_groups.json"


def test_init_and_cache_cloudtrail_logs():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_cloud_watch_log_groups()
        aws_api.cache_objects(aws_api.cloud_watch_log_groups, cloud_watch_cache)
        break

    print(f"len(cloud_watch_log_groups) = {len(aws_api.cloud_watch_log_groups)}")
    assert isinstance(aws_api.cloud_watch_log_groups, list)




def upload_to_s3(dir_to_upload, bucket_name):
    for root, dirs, files in os.walk(dir_to_upload):
        print(root)
        for file in files:
            aws_api.s3_client.client.upload_file(os.path.join(root, file), bucket_name, os.path.join(root, file))
    return

hosted_zones_cache_file = os.path.join(cache_base_path, "hosted_zones.json")

def test_init_and_cache_hosted_zones():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_hosted_zones()
        aws_api.cache_objects(aws_api.hosted_zones, hosted_zones_cache_file)
        #pdb.set_trace()
        break

    assert isinstance(aws_api.iam_roles, list)


classic_load_balancers_cache_file = os.path.join(cache_base_path, "classic_load_balancers.json")


def test_init_and_cache_classic_load_balancers():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_classic_load_balancers()
    aws_api.cache_objects(aws_api.classic_load_balancers, classic_load_balancers_cache_file)

load_balancers_cache_file = os.path.join(cache_base_path, "load_balancers.json")

def test_init_and_cache_load_balancers():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_load_balancers()
        aws_api.cache_objects(aws_api.load_balancers, load_balancers_cache_file)
        break


security_groups_cache_file = os.path.join(cache_base_path, "security_groups.json")


def test_init_and_cache_security_groups():
    for dict_environ in ignore_me.aws_accounts:
        env = AWSAccount()
        env.init_from_dict(dict_environ)
        AWSAccount.set_aws_account(env)
        aws_api.init_security_groups()
        #pdb.set_trace()
        #break
    aws_api.cache_objects(aws_api.security_groups, security_groups_cache_file)

if __name__ == "__main__":
    #test_init_and_cache_ec2instances()
    #test_init_and_cache_s3_buckets()
    #test_init_and_cache_s3_bucket_objects()
    test_init_and_cache_raw_large_cloud_watch_log_groups()
    #test_init_and_cache_lambdas()
    #test_init_and_cache_iam_roles()
    #test_init_and_cache_iam_policies()
    #test_init_and_cache_cloudtrail_logs()
    #test_init_and_cache_hosted_zones()
    #test_init_and_cache_classic_load_balancers()
    #test_init_and_cache_load_balancers()
    #test_init_and_cache_security_groups()
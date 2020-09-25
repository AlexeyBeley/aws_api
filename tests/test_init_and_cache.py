import os
import sys
import pdb

sys.path.insert(0, os.path.abspath("../src"))
sys.path.insert(0, "/Users/alexeybe/private/IP/ip")
sys.path.insert(0, "/Users/alexeybe/private/aws_api/ignore")
sys.path.insert(0, "/Users/alexeybe/private/aws_api/src/base_entities")

from aws_api import AWSAPI
import ignore_me
import logging
logger = logging.Logger(__name__)
from environment import Environment

aws_api = AWSAPI()


def test_init_and_cache_ec2instances():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_ec2_instances()
    aws_api.cache_objects(aws_api.ec2_instances, "/Users/alexeybe/private/aws_api/ignore/cache_objects/ec2_instances.json")

    print(f"len(instances) = {len(aws_api.ec2_instances)}")
    assert isinstance(aws_api.ec2_instances, list)

s3_buckets_cache_file = "/Users/alexeybe/private/aws_api/ignore/cache_objects/s3_buckets.json"
s3_objects_dir = "/Users/alexeybe/private/aws_api/ignore/cache_objects/s3_buckets_objects"

def test_init_and_cache_s3_buckets():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_s3_buckets()
        pdb.set_trace()
    aws_api.cache_objects(aws_api.s3_buckets, s3_buckets_cache_file)

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_s3_bucket_objects():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        #aws_api.init_s3_buckets()
        aws_api.init_s3_buckets(from_cache=True,
                                cache_file=s3_buckets_cache_file)

        aws_api.init_and_cache_s3_bucket_objects(s3_objects_dir)

        pdb.set_trace()

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_lambdas():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_lambdas()

    aws_api.cache_objects(aws_api.lambdas, "/Users/alexeybe/private/aws_api/ignore/cache_objects/lambdas.json")

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_and_cache_iam_roles():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_iam_policies(from_cache=True, cache_file="/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_policies.json")
        aws_api.init_iam_roles()
        aws_api.cache_objects(aws_api.iam_roles, "/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_roles.json")
        break

    print(f"len(iam_roles) = {len(aws_api.iam_roles)}")
    assert isinstance(aws_api.iam_roles, list)


def test_init_and_cache_iam_policies():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_iam_policies()
        aws_api.cache_objects(aws_api.iam_policies, "/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_policies.json")
        break

    print(f"len(iam_roles) = {len(aws_api.iam_policies)}")
    assert isinstance(aws_api.iam_policies, list)

def test_init_and_cache_cloudtrail_logs():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_cloud_watch_log_groups()
        aws_api.cache_objects(aws_api.cloud_watch_log_groups, "/Users/alexeybe/private/aws_api/ignore/cache_objects/cloud_watch_log_groups.json")
        break

    print(f"len(cloud_watch_log_groups) = {len(aws_api.cloud_watch_log_groups)}")
    assert isinstance(aws_api.cloud_watch_log_groups, list)

if __name__ == "__main__":
    #test_init_and_cache_ec2instances()
    #test_init_and_cache_s3_buckets()
    #test_init_and_cache_s3_bucket_objects()
    #test_init_and_cache_lambdas()
    #test_init_and_cache_iam_roles()
    test_init_and_cache_iam_policies()
    #test_init_and_cache_cloudtrail_logs()

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


def test_init_and_cleanup_s3_buckets():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)
        aws_api.init_s3_buckets(full_information=False)

        aws_api.cleanup_report_s3_buckets()

    print(f"len(s3_buckets) = {len(aws_api.s3_buckets)}")
    assert isinstance(aws_api.s3_buckets, list)


def test_init_from_cache_and_cleanup_s3_buckets():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)

        aws_api.init_s3_buckets(from_cache=True,
                            cache_file="/Users/alexeybe/private/aws_api/ignore/cache_objects/s3_buckets.json")

        aws_api.cleanup_report_s3_buckets()


def test_cleanup_report_iam_roles():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)

        aws_api.init_iam_roles(from_cache=True,
                            cache_file="/Users/alexeybe/private/aws_api/ignore/cache_objects/iam_roles.json")

        aws_api.cleanup_report_iam_roles()


def test_init_from_cache_and_cleanup_lambdas():
    for dict_environ in ignore_me.environments:
        env = Environment()
        env.init_from_dict(dict_environ)
        Environment.set_environment(env)

        aws_api.init_lambdas(from_cache=True,
                            cache_file="/Users/alexeybe/private/aws_api/ignore/cache_objects/lambdas.json")

        aws_api.cleanup_report_lambdas()


if __name__ == "__main__":
    #test_init_from_cache_and_cleanup_s3_buckets()
    #test_init_from_cache_and_cleanup_lambdas()
    test_cleanup_report_iam_roles()

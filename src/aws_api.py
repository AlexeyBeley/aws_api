import json
import pdb
import os

from ec2_client import EC2Client
from ec2_instance import EC2Instance

from iam_client import IamClient
from iam_policy import IamPolicy
from iam_user import IamUser


class AWSAPI(object):

    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        self.aws_key_id = aws_key_id
        self.aws_access_secret = aws_access_secret
        self.iam_client = IamClient(aws_key_id, aws_access_secret, region_name, logger)
        self.ec2_client = EC2Client(aws_key_id, aws_access_secret, region_name, logger)
        self.policies = []
        self.ec2_instances = []
        self.users = []

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

    def load_objects_from_cache(self, file_name, class_type):
        with open(file_name) as fil:
            return [class_type(dict_src, from_cache=True) for dict_src in json.load(fil)]

    def cache_objects(self, objects, file_name):
        objects_dicts = [obj.convert_to_dict() for obj in objects]

        if not os.path.exists(os.path.dirname(file_name)):
            os.makedirs(os.path.dirname(file_name))

        with open(file_name, "w") as fil:
            fil.write(json.dumps(objects_dicts))

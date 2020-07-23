import os
import sys
import pdb

sys.path.insert(0, os.path.abspath("../src"))
sys.path.insert(0, "/Users/alexeybe/private/IP/ip")
sys.path.insert(0, "/Users/alexeybe/private/aws_api/ignore")

from aws_api import AWSAPI
import ignore_me
import logging
logger = logging.Logger(__name__)


aws_api = AWSAPI(logger, aws_key_id=ignore_me.aws_key_id, aws_access_secret=ignore_me.aws_access_secret, region_name=ignore_me.region_name)


def test_init_instances():
    logger.warning("\nBla")
    aws_api.init_ec2_instances()
    aws_api.start_assuming_role("arn:aws:iam::711521586476:role/sts-devops-mgmt")
    print(f"len(instances) = {len(aws_api.ec2_instances)}")
    assert isinstance(aws_api.ec2_instances, list)
    #pdb.set_trace()
    aws_api.stop_assuming_role()

#todo:
# test boto3 sessoion from one region can open clients in another regions

if __name__ == "__main__":
    test_init_instances()
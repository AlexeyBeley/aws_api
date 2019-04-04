import pdb
from ec2_instance import EC2Instance
from boto3_client import Boto3Client


class EC2Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "ec2"
        super(EC2Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    def get_all_instances(self):
        final_result = list()
        for instance in self.execute("describe_instances", "Reservations"):
            final_result.extend(instance['Instances'])

        return [EC2Instance(instance) for instance in final_result]

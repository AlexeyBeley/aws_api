"""
AWS ec2 client to handle ec2 service API requests.
"""
from ec2_instance import EC2Instance
from ec2_security_group import EC2SecurityGroup
from boto3_client import Boto3Client
from aws_account import AWSAccount


class EC2Client(Boto3Client):
    """
    Client to handle specific aws service API calls.
    """
    def __init__(self):
        client_name = "ec2"
        super().__init__(client_name)

    def get_all_instances(self):
        """
        Get all ec2 instances in current region.
        :return:
        """
        final_result = list()

        for region in AWSAccount.get_aws_account().regions.values():
            AWSAccount.set_aws_region(region)
            for instance in self.execute(self.client.describe_instances, "Reservations"):
                final_result.extend(instance['Instances'])
        return [EC2Instance(instance) for instance in final_result]

    def get_all_security_groups(self, full_information=False):
        """
        Get all security groups in the region.
        :param full_information:
        :return:
        """
        final_result = list()

        for region in AWSAccount.get_aws_account().regions.values():
            AWSAccount.set_aws_region(region)
            for ret in self.execute(self.client.describe_security_groups, "SecurityGroups"):
                obj = EC2SecurityGroup(ret)
                if full_information is True:
                    raise NotImplementedError()

                final_result.append(obj)

        return final_result

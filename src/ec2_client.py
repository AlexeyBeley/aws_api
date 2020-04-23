import pdb
from ec2_instance import EC2Instance
from ec2_vpc_subnet import EC2VPCSubnet
from ec2_security_group import EC2SecurityGroup
from boto3_client import Boto3Client


class EC2Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "ec2"
        super(EC2Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    @Boto3Client.requires_connection
    def get_ec2_instance_by_ids(self, ids):
        """
        Getting EC2 Instance by their ID.
        :return: list with all EC2.
        :rtype list[EC2Instance]
        Note: returning only the Instances information (unlike AWSToolsBoto3 version).
        """
        raise NotImplementedError()

        final_result = []
        for page in self.client.get_paginator('describe_instances').paginate(Filters=[{'Name': 'instance-id', 'Values': ids}]):
            for instance in page['Reservations']:
                final_result.extend(instance['Instances'])

        ret = self.client.describe_instances(Filters = [{'Name':'instance-id', 'Values': ids}])
        for x in ret["Reservations"]: print(x)

        final_result = list()
        for page in self.client.get_paginator('describe_instances').paginate():
            for instance in page['Reservations']:
                final_result.extend(instance['Instances'])

        return [EC2Instance(instance) for instance in final_result]

    @Boto3Client.requires_connection
    def get_all_instances(self):
        final_result = list()
        for instance in self.execute(self.client.describe_instances, "Reservations"):
            final_result.extend(instance['Instances'])

        return [EC2Instance(instance) for instance in final_result]

    @Boto3Client.requires_connection
    def get_all_vpc_subnets(self, full_information=False):
        final_result = list()
        for ret in self.execute(self.client.describe_subnets, "Subnets"):
            obj = EC2VPCSubnet(ret)
            if full_information is True:
                raise NotImplementedError

            final_result.append(obj)

        return final_result

    @Boto3Client.requires_connection
    def get_all_security_groups(self, full_information=False):
        final_result = list()
        for ret in self.execute(self.client.describe_security_groups, "SecurityGroups"):
            obj = EC2SecurityGroup(ret)
            if full_information is True:
                raise NotImplementedError

            final_result.append(obj)

        return final_result

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

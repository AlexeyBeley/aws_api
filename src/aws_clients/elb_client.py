import pdb
from boto3_client import Boto3Client
from elb_load_balancer import ClassicLoadBalancer
from aws_account import AWSAccount


class ELBClient(Boto3Client):
    def __init__(self):
        client_name = "elb"
        super(ELBClient, self).__init__(client_name)

    def get_all_load_balancers(self, full_information=True):
        final_result = list()

        for region in AWSAccount.get_aws_account().regions.values():
            AWSAccount.set_aws_region(region)
            for response in self.execute(self.client.describe_load_balancers, "LoadBalancerDescriptions"):
                obj = ClassicLoadBalancer(response)
                final_result.append(obj)

                if full_information:
                    pass

        return final_result


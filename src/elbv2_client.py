import pdb
from boto3_client import Boto3Client
from elbv2_load_balancer import LoadBalancer
from elbv2_target_group import ELBV2TargetGroup


class ELBV2Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "elbv2"
        super(ELBV2Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    def get_all_load_balancers(self, full_information=True):
        final_result = list()
        for response in self.execute("describe_load_balancers", "LoadBalancers"):

            obj = LoadBalancer(response)
            final_result.append(obj)

            if full_information:
                pass
                # update_info = self.execute("get_bucket_acl", "Grants", filters_req={"Bucket": obj.name})
                # obj.update_acl(update_info)
                # update_info = self.execute("get_bucket_policy", "Policy", filters_req={"Bucket": "checkout-plugins-public"})
                # obj.update_policy(update_info)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

    def get_all_target_groups(self, full_information=True):
        final_result = list()
        for response in self.execute("describe_target_groups", "TargetGroups"):

            obj = ELBV2TargetGroup(response)
            final_result.append(obj)

            if full_information:
                pass
                # update_info = self.execute("get_bucket_acl", "Grants", filters_req={"Bucket": obj.name})
                # obj.update_acl(update_info)
                # update_info = self.execute("get_bucket_policy", "Policy", filters_req={"Bucket": "checkout-plugins-public"})
                # obj.update_policy(update_info)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

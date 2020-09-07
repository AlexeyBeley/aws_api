import pdb
from boto3_client import Boto3Client
from elb_load_balancer import ClassicLoadBalancer


class ELBClient(Boto3Client):
    def __init__(self):
        client_name = "elb"
        super(ELBClient, self).__init__(client_name)

    def get_all_load_balancers(self, full_information=True):
        final_result = list()

        for response in self.execute(self.client.describe_load_balancers, "LoadBalancerDescriptions"):
            obj = ClassicLoadBalancer(response)
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


import pdb
from boto3_client import Boto3Client
from  aws_lambda import AWSLambda


class LambdaClient(Boto3Client):
    def __init__(self):
        client_name = "lambda"
        super(LambdaClient, self).__init__(client_name)

    def get_all_lambdas(self, full_information=True):
        final_result = list()

        for response in self.execute(self.client.list_functions, "Functions"):
            obj = AWSLambda(response)
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


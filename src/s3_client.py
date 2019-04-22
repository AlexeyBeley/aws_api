import pdb
from boto3_client import Boto3Client
from s3_bucket import S3Bucket


class S3Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "s3"
        super(S3Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    def get_all_buckets(self, full_information=True):
        final_result = list()
        for response in self.execute("list_buckets", "Buckets"):

            obj = S3Bucket(response)
            final_result.append(obj)

            if full_information:
                update_info = self.execute("get_bucket_acl", "Grants", filters_req={"Bucket": obj.name})
                obj.update_acl(update_info)
                update_info = self.execute("get_bucket_policy", "Policy", filters_req={"Bucket": "checkout-plugins-public"})
                obj.update_policy(update_info)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result


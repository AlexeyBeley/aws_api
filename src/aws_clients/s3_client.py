import pdb
from boto3_client import Boto3Client
from s3_bucket import S3Bucket


class S3Client(Boto3Client):
    def __init__(self):
        client_name = "s3"
        super(S3Client, self).__init__(client_name)

    def get_all_buckets(self, full_information=True):
        final_result = list()
        for response in self.execute(self.client.list_buckets, "Buckets"):

            obj = S3Bucket(response)
            final_result.append(obj)

            if full_information:
                update_info = list(self.execute(self.client.get_bucket_acl, "Grants", filters_req={"Bucket": obj.name}))
                obj.update_acl(update_info)

                try:
                    for update_info in self.execute(self.client.get_bucket_policy, "Policy", filters_req={"Bucket": obj.name}):
                        obj.update_policy(update_info)
                except Exception as inst:
                    if "NoSuchBucketPolicy" not in repr(inst):
                        raise

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

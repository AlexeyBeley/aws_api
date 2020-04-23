import pdb
from boto3_client import Boto3Client
from s3_bucket import S3Bucket
import json


class S3Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "s3"
        super(S3Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    @Boto3Client.requires_connection
    def get_all_buckets_(self, full_information=True):
        final_result = list()
        for response in self.execute(self.client.list_buckets, "Buckets"):

            obj = S3Bucket(response)
            final_result.append(obj)

            if full_information:
                # acl
                #update_info = list(self.execute(self.client.get_bucket_acl, "Grants", filters_req={"Bucket": obj.name}))
                #obj.update_acl(update_info)

                # policy
                #try:
                #    for update_info in self.execute(self.client.get_bucket_policy, "Policy", filters_req={"Bucket": obj.name}):
                #        obj.update_policy(update_info)
                #except Exception as inst:
                #    if "NoSuchBucketPolicy" not in repr(inst):
                #        raise

                # Contents
                try:
                    update_info_objects = list(self.execute(self.client.list_objects_v2, "Contents", filters_req={"Bucket": obj.name}))
                except KeyError as e:
                    if "Contents" not in repr(e):
                        raise
                    update_info_objects = []
                obj.update_contents(update_info_objects)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

    @Boto3Client.requires_connection
    def get_large_bucket(self, bucket_name, file_name_prefix):
        lst_buckets = list(self.execute(self.client.list_buckets, "Buckets"))
        for response in lst_buckets:
            obj = S3Bucket(response)
            if obj.name != bucket_name:
                continue
            try:
                print("Updating bucket contents: {}".format(obj.name))
                lst_to_cache = []
                file_counter = 0
                for update_info_object in self.execute(self.client.list_objects_v2, "Contents", filters_req={"Bucket": obj.name}):
                    lst_to_cache.append(update_info_object)
                    update_info_object["LastModified"] = str(update_info_object["LastModified"])
                    if len(lst_to_cache) > 1000000:
                        self.logger.info("Writing new chunk of data to {}".format("cache/large_bucket/s3_large_bucket_{}.{}.json".format(obj.name, file_counter)))
                        with open("cache/large_bucket/s3_large_bucket_{}.{}.json".format(obj.name, file_counter), "w") as fil:
                            fil.write(json.dumps(lst_to_cache))
                        lst_to_cache = []
                        file_counter += 1

                print("update_info_objects for bucket {} {}".format(obj.name, update_info_object))
            except KeyError as e:
                if "Contents" not in repr(e):
                    raise

        return obj

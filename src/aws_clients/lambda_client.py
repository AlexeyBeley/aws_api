import pdb
from boto3_client import Boto3Client
from  aws_lambda import AWSLambda


class LambdaClient(Boto3Client):
    NEXT_PAGE_REQUEST_KEY = "Marker"
    NEXT_PAGE_RESPONSE_KEY = "NextMarker"
    NEXT_PAGE_INITIAL_KEY = ""

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

    def temp(self):
        try:
            start_after = ""
            while start_after is not None:
                counter = 0
                for object_info in self.execute(self.client.list_objects_v2, "Contents", filters_req={"Bucket": obj.name, "StartAfter": start_after}):
                    counter += 1
                    bucket_object = S3Bucket.BucketObject(object_info)
                    yield bucket_object

                start_after = bucket_object.key if counter == 1000 else None

        except Exception as inst:
            if "AccessDenied" in repr(inst):
                print(f"Init bucket full information failed {obj.name}: {repr(inst)}")
            else:
                raise
import pdb
from boto3_client import Boto3Client
from route53_hosted_zone import HostedZone


class Route53Client(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "route53"
        super(Route53Client, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    def get_all_hosted_zones(self, full_information=True):
        final_result = list()

        for response in self.execute("list_hosted_zones", "HostedZones"):

            obj = HostedZone(response)

            if full_information:
                update_info = self.execute("list_resource_record_sets", "ResourceRecordSets", filters_req={"HostedZoneId": obj.id})
                obj.update_record_set(update_info)

            final_result.append(obj)
            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result


import pdb
from boto3_client import Boto3Client
from cloud_watch_log_group import CloudWatchLogGroup
from common_utils import CommonUtils


class CloudWatchLogsClient(Boto3Client):
    NEXT_PAGE_REQUEST_KEY = "nextToken"
    NEXT_PAGE_RESPONSE_KEY = "nextToken"
    NEXT_PAGE_INITIAL_KEY = ""

    def __init__(self):
        client_name = "logs"
        super(CloudWatchLogsClient, self).__init__(client_name)

    def get_cloud_watch_log_groups(self, full_information=False):
        final_result = list()

        for result in self.execute(self.client.describe_log_groups, "logGroups"):
            obj = CloudWatchLogGroup(result)
            if full_information:
                self.update_log_group_full_information(obj)
            #pdb.set_trace()
            final_result.append(obj)
        pdb.set_trace()
        return final_result

    def update_log_group_full_information(self, obj):
        """
        Fetches and updates obj
        :param obj:
        :return: None, raise if fails
        """
        pdb.set_trace()
        for response in self.execute(self.client.get_policy_version, "PolicyVersion", filters_req={"PolicyArn": policy.arn, "VersionId": policy.default_version_id}):
            obj.update_statements(response)

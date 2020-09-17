import pdb
from iam_user import IamUser
from iam_access_key import IamAccessKey
from iam_policy import IamPolicy
from boto3_client import Boto3Client
from iam_role import IamRole
from common_utils import CommonUtils


class IamClient(Boto3Client):
    NEXT_PAGE_REQUEST_KEY = "Marker"
    NEXT_PAGE_RESPONSE_KEY = "Marker"
    NEXT_PAGE_INITIAL_KEY = ""

    def __init__(self):
        client_name = "iam"
        super(IamClient, self).__init__(client_name)

    def get_all_users(self, full_information=True):
        final_result = list()

        for response in self.execute(self.client.list_users, "Users"):
            user = IamUser(response)
            final_result.append(user)

        if full_information:
            for update_info in self.execute(self.client.get_account_authorization_details, "UserDetailList"):
                user = CommonUtils.find_objects_by_values(final_result, {"id": update_info["UserId"]}, max_count=1)[0]
                user.update_attributes(update_info)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

    def update_policy_statements(self, policy):
        """
        Fetches and pdates the policy statements
        :param policy: The IamPolicy obj
        :return: None, raise if fails
        """
        pdb.set_trace()
        for response in self.execute(self.client.get_policy_version, "PolicyVersion", filters_req={"PolicyArn": policy.arn, "VersionId": policy.default_version_id}):
            policy.update_statements(response)

    def get_all_access_keys(self):
        final_result = list()
        users = self.get_all_users()

        for user in users:
            for result in self.execute(self.client.list_access_keys, "AccessKeyMetadata", filters_req={"UserName": user.name}):
                final_result.append(IamAccessKey(result))

        return final_result

    def get_all_roles(self, full_information=True, policies=None):
        final_result = list()

        for result in self.execute(self.client.list_roles, "Roles", filters_req={"MaxItems": 1000}):
            role = IamRole(result)
            final_result.append(role)
            if full_information:
                self.update_iam_role_full_information(role, policies)

        return final_result

    def update_iam_role_full_information(self, iam_role, policies):
        """
        list_role_policies:
        ('RoleName', 'dome9qa-WebAppRole-XACEAB4O73X2')
        ('PolicyName', 'AmazonEC2ReadOnlyAccess')
        ('PolicyDocument', {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'ec2:Describe*', 'Resource': '*'}, {'Effect': 'Allow', 'Action': 'elasticloadbalancing:Describe*', 'Resource': '*'}, {'Effect': 'Allow', 'Action': ['cloudwatch:ListMetrics', 'cloudwatch:GetMetricStatistics', 'cloudwatch:Describe*'], 'Resource': '*'}, {'Effect': 'Allow', 'Action': 'autoscaling:Describe*', 'Resource': '*'}]})
        ('ResponseMetadata', {'RequestId': 'dcc6b611-786c-4ef7-a7d3-a7c391755326', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'dcc6b611-786c-4ef7-a7d3-a7c391755326', 'content-type': 'text/xml', 'content-length': '1963', 'date': 'Thu, 17 Sep 2020 07:49:30 GMT'}, 'RetryAttempts': 0})

        :param iam_role:
        :param policies:
        :return:
        """
        if iam_role.name != "dome9qa-WebAppRole-XACEAB4O73X2":
            return

        self.update_iam_role_last_used(iam_role)
        self.update_iam_role_managed_policies(iam_role, policies)
        self.update_iam_role_inline_policies(iam_role)

    def update_iam_role_last_used(self, iam_role):
        ret = self.execute(self.client.get_role, "Role", filters_req={"RoleName": iam_role.name})
        update_info = next(ret)
        iam_role.update_extended(update_info)

    def update_iam_role_managed_policies(self, iam_role, policies):
        for managed_policy in self.execute(self.client.list_attached_role_policies, "AttachedPolicies", filters_req={"RoleName": iam_role.name, "MaxItems": 1000}):
            policy = CommonUtils.find_objects_by_values(policies, {"arn": managed_policy["PolicyArn"]}, max_count=1)[0]
            iam_role.add_policy(policy)

    def update_iam_role_inline_policies(self, iam_role):
        for poilcy_name in self.execute(self.client.list_role_policies, "PolicyNames", filters_req={"RoleName": iam_role.name, "MaxItems": 1000}):
            for document_dict in self.execute(self.client.get_role_policy, "PolicyDocument", filters_req={"RoleName": iam_role.name, "PolicyName": poilcy_name}):
                policy_dict = {"PolicyName": poilcy_name}
                policy = IamPolicy(policy_dict)
                iam_role.add_policy(policy)

                policy_dict = {"Document": document_dict}
                policy.update_statements(policy_dict)

    def get_all_policies(self, full_information=True):
        final_result = list()

        for result in self.execute(self.client.list_policies, "Policies"):
            pol = IamPolicy(result)
            if full_information:
                self.update_policy_statements(pol)
            #pdb.set_trace()
            final_result.append(pol)
        return final_result

    def update_policy_statements(self, policy):
        """
        Fetches and pdates the policy statements
        :param policy: The IamPolicy obj
        :return: None, raise if fails
        """
        for response in self.execute(self.client.get_policy_version, "PolicyVersion", filters_req={"PolicyArn": policy.arn, "VersionId": policy.default_version_id}):
            policy.update_statements(response)

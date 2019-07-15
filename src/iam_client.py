import pdb
from iam_user import IamUser
from iam_access_key import IamAccessKey
from iam_policy import IamPolicy
from boto3_client import Boto3Client
from iam_role import IamRole
from common_utils import CommonUtils


class IamClient(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "iam"
        super(IamClient, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    @Boto3Client.requires_connection
    def get_all_users(self, full_information=True):
        final_result = list()

        for response in self.execute(self.client.list_users, "Users"):
            user = IamUser(response)
            final_result.append(user)

        if full_information:
            response = self.execute(self.client.get_account_authorization_details, "UserDetailList")
            for update_info in response:
                user = CommonUtils.find_objects_by_values(final_result, {"id": update_info["UserId"]}, max_count=1)[0]
                user.update_attributes(update_info)

            # import pprint
            # printer = pprint.PrettyPrinter(indent=4)
            # for user in ret:  printer.pprint(user)
        return final_result

    @Boto3Client.requires_connection
    def update_policy_statements(self, policy):
        """
        Fetches and pdates the policy statements
        :param policy: The IamPolicy obj
        :return: None, raise if fails
        """
        # response = self.client.get_policy_version(PolicyArn='arn:aws:iam::919141998999:policy/configs-getter-production-role-policy', VersionId=policy.default_version_id)
        response = self.execute(self.client.get_policy_version, "PolicyVersion", filters_req={"PolicyArn": policy.arn, "VersionId": policy.default_version_id})
        policy.update_statements(response)

    @Boto3Client.requires_connection
    def get_all_access_keys(self):
        final_result = list()
        users = self.get_all_users()

        for user in users:
            for result in self.execute(self.client.list_access_keys, "AccessKeyMetadata", filters_req={"UserName": user.name}):
                final_result.append(IamAccessKey(result))

        return final_result

    @Boto3Client.requires_connection
    def get_all_roles(self):
        final_result = list()

        for result in self.execute(self.client.list_roles, "Roles"):
            final_result.append(IamRole(result))

    @Boto3Client.requires_connection
    def get_all_policies(self, full_inforamtion=True):
        """
        response = self.client.get_policy_version(PolicyArn=policy.arn)

        response = client.list_entities_for_policy(PolicyArn='arn:aws:iam::919141998999:policy/configs-getter-production-role-policy')

        #ret = self.client.get_account_authorization_details()
        #for usr_det in ret["UserDetailList"]: print(usr_det)
        response = self.client.get_role(RoleName='configs-getter-production-role')
        response["Role"]
        client = self.client
        response = self.client.list_roles()
        response["Roles"]
        response = client.list_instance_profiles_for_role(RoleName='configs-getter-production-role')
        response["InstanceProfiles"]

        # get role attached to policy
        response = client.list_entities_for_policy(PolicyArn='arn:aws:iam::919141998999:policy/configs-getter-production-role-policy')
        response["PolicyRoles"][0]["RoleName"]
        response["PolicyRoles"][0]["RoleId"]


        #AttachmentCount - how many attached entities
        response = client.get_policy(PolicyArn='arn:aws:iam::919141998999:policy/configs-getter-production-role-policy')
        response["Policy"]


        for result in self.client.get_role_policy(RoleName='xl-writer-unauth-testing',PolicyName=''): lst_ret.append(result)


        pdb.set_trace()
        response = client.get_role_policy(
            RoleName='string',
            PolicyName='string'
        )

        return final_result
        :return:
        """
        final_result = list()

        for result in self.execute(self.client.list_policies, "Policies"):
            pol = IamPolicy(result)
            if full_inforamtion:
                self.update_policy_statements(pol)

            final_result.append(pol)
        return final_result

    @Boto3Client.requires_connection
    def update_policy_statements(self, policy):
        """
        Fetches and pdates the policy statements
        :param policy: The IamPolicy obj
        :return: None, raise if fails
        """
        # response = self.client.get_policy_version(PolicyArn='arn:aws:iam::919141998999:policy/configs-getter-production-role-policy', VersionId=policy.default_version_id)
        response = self.execute(self.client.get_policy_version, "PolicyVersion", filters_req={"PolicyArn": policy.arn, "VersionId": policy.default_version_id})
        policy.update_statements(response)

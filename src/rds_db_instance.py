import pdb

import socket
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject
from ip import IP

class DBInstance(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(DBInstance, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "LoadBalancerName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "DNSName": self.init_default_attr,
                        "DBInstanceIdentifier": self.init_db_instance_identifier,
                        "DBInstanceClass": self.init_default_attr,
                        "Engine": self.init_default_attr,
                        "DBInstanceStatus": self.init_default_attr,
                        "MasterUsername": self.init_default_attr,
                        "Endpoint": self.init_default_attr,
                        "AllocatedStorage": self.init_default_attr,
                        "InstanceCreateTime": self.init_default_attr,
                        "PreferredBackupWindow": self.init_default_attr,
                        "BackupRetentionPeriod": self.init_default_attr,
                        "DBSecurityGroups": self.init_default_attr,
                        "VpcSecurityGroups": self.init_default_attr,
                        "DBParameterGroups": self.init_default_attr,
                        "AvailabilityZone": self.init_default_attr,
                        "DBSubnetGroup": self.init_default_attr,
                        "PreferredMaintenanceWindow": self.init_default_attr,
                        "PendingModifiedValues": self.init_default_attr,
                        "LatestRestorableTime": self.init_default_attr,
                        "MultiAZ": self.init_default_attr,
                        "EngineVersion": self.init_default_attr,
                        "AutoMinorVersionUpgrade": self.init_default_attr,
                        "ReadReplicaDBInstanceIdentifiers": self.init_default_attr,
                        "LicenseModel": self.init_default_attr,
                        "OptionGroupMemberships": self.init_default_attr,
                        "PubliclyAccessible": self.init_default_attr,
                        "StorageType": self.init_default_attr,
                        "DbInstancePort": self.init_default_attr,
                        "StorageEncrypted": self.init_default_attr,
                        "KmsKeyId": self.init_default_attr,
                        "DbiResourceId": self.init_default_attr,
                        "CACertificateIdentifier": self.init_default_attr,
                        "DomainMemberships": self.init_default_attr,
                        "CopyTagsToSnapshot": self.init_default_attr,
                        "MonitoringInterval": self.init_default_attr,
                        "DBInstanceArn": self.init_default_attr,
                        "IAMDatabaseAuthenticationEnabled": self.init_default_attr,
                        "PerformanceInsightsEnabled": self.init_default_attr,
                        "DeletionProtection": self.init_default_attr,
                        "EnhancedMonitoringResourceArn": self.init_default_attr,
                        "MonitoringRoleArn": self.init_default_attr,
                        "DBName": self.init_default_attr,
                        "ReadReplicaSourceDBInstanceIdentifier": self.init_default_attr,
                        "StatusInfos": self.init_default_attr,
                        "SecondaryAvailabilityZone": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def init_db_instance_identifier(self, key_name, value):
        if self.name is not None:
            return

        self.name = value


    def _init_object_from_cache(self, dict_src):
        options = {}
        self._init_from_cache(dict_src, options)

    def get_dns_records(self):
        """

        :return: list of self dns records, [] else
        """
        ret = [self.endpoint["Address"]] if self.endpoint["Address"] else []
        return ret

    def get_security_groups_endpoints(self):
        """
        Get sg ids, specified in this rds if there is "inactive" raises Exception

        :return:
        """
        ret = []
        for sg in self.vpc_security_groups:
            if sg["Status"] != "active":
                raise Exception
            endpoint = {"sg_id": sg["VpcSecurityGroupId"]}
            endpoint["dns"] = self.endpoint["Address"]
            endpoint["port"] = self.endpoint["Port"]

            endpoint["description"] = "rds: {}".format(self.name)
            ret.append(endpoint)

        return ret

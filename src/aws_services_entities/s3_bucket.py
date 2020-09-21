import pdb

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class S3Bucket(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        self.acl = None
        self.policy = None
        self.bucket_objects = []

        super(S3Bucket, self).__init__(dict_src)
        if from_cache:
            self._init_bucket_from_cashe(dict_src)
            return

        init_options = {
                        "Name": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                        "CreationDate": self.init_default_attr
                        }

        self.init_attrs(dict_src, init_options)

    def _init_bucket_from_cashe(self, dict_src):
        options = {
                   'creation_date':  self.init_date_attr_from_cache_string,
                   'acl':  self._init_acl_from_cache,
                   'policy':  self._init_policy_from_cache,
                   }

        self._init_from_cache(dict_src, options)

    def _init_acl_from_cache(self, _, dict_src):
        if dict_src is None:
            return

        if self.acl is None:
            self.acl = S3Bucket.ACL(dict_src, from_cache=True)
        else:
            raise NotImplementedError

    def _init_policy_from_cache(self, key, dict_src):
        if self.policy is not None:
            raise NotImplementedError

        if dict_src is not None:
            self.policy = S3Bucket.Policy(dict_src, from_cache=True)

    def update_objects(self, lst_src, from_cache=False):
        for dict_object in lst_src:
            bucket_object = S3Bucket.BucketObject(dict_object, from_cache=from_cache)
            self.bucket_objects.append(bucket_object)

    def update_acl(self, lst_src):
        if self.acl is None:
            self.acl = S3Bucket.ACL(lst_src)
        else:
            raise NotImplementedError()

    def update_policy(self, str_src):
        if self.policy is None:
            self.policy = S3Bucket.Policy(str_src)
        else:
            raise NotImplementedError()

    class ACL(AwsObject):
        def __init__(self, src_data, from_cache=False):
            super(S3Bucket.ACL, self).__init__(src_data)
            self.grants = []

            if from_cache:
                if type(src_data) is not dict:
                    pdb.set_trace()
                    raise TypeError
                self._init_acl_from_cache(src_data)
                return

            if type(src_data) is not list:
                pdb.set_trace()
                raise TypeError

            for dict_grant in src_data:
                grant = self.Grant(dict_grant)
                self.grants.append(grant)

        def _init_acl_from_cache(self, dict_src):
            options = {
                       'grants': self._init_grants_from_cache,
                       }

            self._init_from_cache(dict_src, options)

        def _init_grants_from_cache(self, _, lst_src):
            if self.grants:
                raise NotImplementedError
            else:
                for dict_grant in lst_src:
                    grant = self.Grant(dict_grant, from_cache=True)
                    self.grants.append(grant)

        class Grant(AwsObject):
            def __init__(self, dict_src, from_cache=False):
                super(S3Bucket.ACL.Grant, self).__init__(dict_src)
                if from_cache:
                    self._init_grant_from_cashe(dict_src)
                    return

                init_options = {
                    "Grantee": self.init_default_attr,
                    "Permission": self.init_default_attr
                }

                self.init_attrs(dict_src, init_options)

            def _init_grant_from_cashe(self, dict_src):
                options = {}

                self._init_from_cache(dict_src, options)

    class Policy(AwsObject):
        def __init__(self, src_, from_cache=False):
            if type(src_) is str:
                dict_src = json.loads(src_)
            else:
                if from_cache:
                    self._init_policy_from_cashe(src_)
                    return
                else:
                    raise NotImplementedError

            super(S3Bucket.Policy, self).__init__(dict_src)
            if from_cache:
                raise NotImplementedError

            init_options = {
                "Version": self.init_default_attr,
                "Statement": self.init_default_attr,
                "Id": self.init_default_attr,
            }

            self.init_attrs(dict_src, init_options)

        def _init_policy_from_cashe(self, dict_src):
            options = {}
            try:
                self._init_from_cache(dict_src, options)
            except Exception:
                print(dict_src)
                raise

    class BucketObject(AwsObject):
        def __init__(self, src_data, from_cache=False):
            self.key = None
            super(S3Bucket.BucketObject, self).__init__(src_data)

            if from_cache:
                if type(src_data) is not dict:
                    raise TypeError()
                self._init_bucket_object_from_cache(src_data)
                return

            if type(src_data) is not dict:
                raise TypeError()

            self.key = src_data["Key"]

        def _init_bucket_object_from_cache(self, dict_src):
            options = {}
            self._init_from_cache(dict_src, options)

            self.init_date_attr_from_formatted_string("LastModified", dict_src["dict_src"]["LastModified"])
            self.size = dict_src["dict_src"]["Size"]

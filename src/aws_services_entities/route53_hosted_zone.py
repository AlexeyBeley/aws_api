import pdb

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.abspath("../.."), "IP", "ip", "src"))

from aws_object import AwsObject


class HostedZone(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        self.records = []
        super(HostedZone, self).__init__(dict_src)
        if from_cache:
            self._init_object_from_cache(dict_src)
            return

        init_options = {
                        "Id": lambda x, y: self.init_default_attr(x, y, formatted_name="id"),
                        "Name": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                        "CallerReference": self.init_default_attr,
                        "Config": self.init_default_attr,
                        "ResourceRecordSetCount": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_object_from_cache(self, dict_src):
        options = {"records": self._init_records_from_cache}
        self._init_from_cache(dict_src, options)

    def update_record_set(self, dict_src):
        self.records.append(self.Record(dict_src))

    def _init_records_from_cache(self, key, lst_src):
        if self.records:
            raise NotImplementedError
        else:
            for record in lst_src:
                self.records.append(self.Record(record, from_cache=True))

    class Record(AwsObject):
        def __init__(self, dict_src, from_cache=False):

            super(HostedZone.Record, self).__init__(dict_src)
            if from_cache:
                self._init_object_from_cache(dict_src)
                return

            init_options = {
                "Name": lambda x, y: self.init_default_attr(x, y, formatted_name="name"),
                "Type": self.init_default_attr,
                "AliasTarget": self.init_default_attr,
                "TTL": self.init_default_attr,
                "ResourceRecords": self.init_default_attr,
            }

            self.init_attrs(dict_src, init_options)

        def _init_object_from_cache(self, dict_src):
            options = {}
            self._init_from_cache(dict_src, options)
from aws_object import AwsObject
import pdb
from cloudwatch_log_stream import CloudwatchLogStream


class CloudwatchLogGroup(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        self.log_streams = None
        self.retention_in_days = None

        super(CloudwatchLogGroup, self).__init__(dict_src)

        if from_cache:
            self._init_group_from_cashe(dict_src)
            return

        init_options = {
                        "logGroupName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "creationTime": self.init_default_attr,
                        "metricFilterCount": self.init_default_attr,
                        "arn": self.init_default_attr,
                        "storedBytes": self.init_default_attr,
                        "retentionInDays": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_group_from_cashe(self, dict_src):
        options = {
                   'log_streams': lambda x, y: self.init_cloudwatch_log_streams_from_cache(x, y, from_cache=True)
                   }

        self._init_from_cache(dict_src, options)

    def init_cloudwatch_log_streams_from_cache(self, _, streams, from_cache=False):
        self.log_streams = [CloudwatchLogStream(dict_stream, from_cache=from_cache) for dict_stream in streams]

    def init_cloudwatch_log_streams(self, streams):
        self.log_streams = [CloudwatchLogStream(dict_stream) for dict_stream in streams]

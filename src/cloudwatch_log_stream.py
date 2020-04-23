from aws_object import AwsObject
import pdb


class CloudwatchLogStream(AwsObject):
    def __init__(self, dict_src, from_cache=False):
        super(CloudwatchLogStream, self).__init__(dict_src)
        if from_cache:
            self._init_stream_from_cashe(dict_src)
            return

        init_options = {
                        "logStreamName": lambda x, y: self.init_default_attr(x, y, formated_name="name"),
                        "creationTime": self.init_default_attr,
                        "firstEventTimestamp": self.init_default_attr,
                        "lastEventTimestamp": self.init_default_attr,
                        "lastIngestionTime": self.init_default_attr,
                        "uploadSequenceToken": self.init_default_attr,
                        "arn": self.init_default_attr,
                        "storedBytes": self.init_default_attr,
                        }

        self.init_attrs(dict_src, init_options)

    def _init_stream_from_cashe(self, dict_src):
        options = {}
        self._init_from_cache(dict_src, options)

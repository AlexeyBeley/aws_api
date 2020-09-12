import re
import pdb
import datetime


class AwsObject(object):
    #  for x, y in dict_src.items(): print('"'+str(x)+'"' +": "+ "self.init_default_attr" + ",")
    #  compile re for Name usage

    # Regex for manipulating CamelCase attr names
    _FIRST_CAP_RE = re.compile('(.)([A-Z][a-z]+)')
    _ALL_CAP_RE = re.compile('([a-z0-9])([A-Z])')

    def __init__(self, dict_src, from_cache=False):
        if from_cache:
            self.dict_src = None
        else:
            self.dict_src = dict_src
        self.name = None
        self.id = None

    def _init_from_cache(self, dict_src, dict_options):
        for key_src, value in dict_src.items():
            if key_src in dict_options:
                dict_options[key_src](key_src, value)
            else:
                self.init_default_attr(key_src, value)

    @property
    def h_class_name(self):
        return self.__class__.__name__

    @h_class_name.setter
    def h_class_name(self, _):
        raise Exception("System parameter, can't set")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value

    def init_default_attr(self, attr_name, value, formated_name=None):
        if formated_name is None:
            formated_name = self.format_attr_name(attr_name)
        setattr(self, formated_name, value)

    def init_date_attr_from_formatted_string(self, attr_name, value):
        """
        "%Y-%m-%d %H:%M:%S:%f%z"

        :param attr_name:
        :param value:
        :return:
        """

        datetime_object = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S:%f%z")
        setattr(self, attr_name, datetime_object)

    def init_date_attr_from_cache_string(self, attr_name, value):
        """

        :param attr_name:
        :param value:
        :return:
        """
        if "+" not in value:
            raise NotImplementedError
        # To use %z : "2017-07-26 15:54:10+01:00" -> "2017-07-26 15:54:10+0100"
        index = value.rfind(":")
        value = value[:index] + value[index+1:]

        # Example: strptime('2017-07-26 15:54:10+0000', '%Y-%m-%d %H:%M:%S%z')
        datetime_object = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S%z")
        setattr(self, attr_name, datetime_object)

    def init_attrs(self, dict_src, dict_options):
        for key_src, value in dict_src.items():
            try:
                dict_options[key_src](key_src, value)
            except KeyError:
                for key_src_, value_ in dict_src.items():
                    if key_src_ not in dict_options:
                        print('"{}":  self.init_default_attr,'.format(key_src_))

                raise self.UnknownKeyError("Unknown key: " + key_src)

    def update_attributes(self, dict_src):
        for key_src, value in dict_src.items():
            self.init_default_attr(key_src, value)

    def format_attr_name(self, name):
        # shamelessly copied from https://stackoverflow.com/a/1176023
        """
        format_attr_name('CamelCase')
        'camel_case'
        format_attr_name('CamelCamelCase')
        'camel_camel_case'
        format_attr_name('Camel2Camel2Case')
        'camel2_camel2_case'
        format_attr_name('getHTTPResponseCode')
        'get_http_response_code'
        format_attr_name('get2HTTPResponseCode')
        'get2_http_response_code'
        format_attr_name('HTTPResponseCode')
        'http_response_code'
        format_attr_name('HTTPResponseCodeXYZ')
        'http_response_code_xyz'
        :param name:
        :return:
        """

        s1 = self._FIRST_CAP_RE.sub(r'\1_\2', name)
        s1 = s1.replace("__", "_")
        return self._ALL_CAP_RE.sub(r'\1_\2', s1).lower()

    def convert_to_dict(self):
        return self.convert_to_dict_static(self.__dict__)

    @staticmethod
    def convert_to_dict_static(obj_src, custom_types=None):
        if type(obj_src) in [str, int, bool, type(None)]:
            return obj_src
        elif type(obj_src) == dict:
            ret = {}
            for key, value in obj_src.items():
                if type(key) not in [int, str]:
                    raise Exception
                ret[key] = AwsObject.convert_to_dict_static(value, custom_types=custom_types)
            return ret
        elif type(obj_src) == list:
            return [AwsObject.convert_to_dict_static(value, custom_types=custom_types) for value in obj_src]
        elif isinstance(obj_src, AwsObject):
            return obj_src.convert_to_dict()
        elif isinstance(obj_src, datetime.datetime):
            pdb.set_trace()
        else:
            # In most cases it will become str
            # Ugly but efficient
            if not custom_types:
                return str(obj_src)

            if type(obj_src) not in custom_types:
                return str(obj_src)

            return custom_types[type(obj_src)](obj_src)

    class UnknownKeyError(Exception):
        pass

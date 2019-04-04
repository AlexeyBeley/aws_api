import re
import pdb


class AwsObject:
    #  for x, y in dict_src.items(): print('"'+str(x)+'"' +": "+ "self.init_default_attr" + ",")
    #  compile re for Name usage
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

    def init_date_attr_from_cache_string(self, attr_name, value):
        """
        %a	Weekday as locale’s abbreviated name.
        Sun, Mon, …, Sat (en_US);
        So, Mo, …, Sa (de_DE)
        (1)
        %A	Weekday as locale’s full name.
        Sunday, Monday, …, Saturday (en_US);
        Sonntag, Montag, …, Samstag (de_DE)
        (1)
        %w	Weekday as a decimal number, where 0 is Sunday and 6 is Saturday.	0, 1, …, 6
        %d	Day of the month as a zero-padded decimal number.	01, 02, …, 31
        %b	Month as locale’s abbreviated name.
        Jan, Feb, …, Dec (en_US);
        Jan, Feb, …, Dez (de_DE)
        (1)
        %B	Month as locale’s full name.
        January, February, …, December (en_US);
        Januar, Februar, …, Dezember (de_DE)
        (1)
        %m	Month as a zero-padded decimal number.	01, 02, …, 12
        %y	Year without century as a zero-padded decimal number.	00, 01, …, 99
        %Y	Year with century as a decimal number.	1970, 1988, 2001, 2013
        %H	Hour (24-hour clock) as a zero-padded decimal number.	00, 01, …, 23
        %I	Hour (12-hour clock) as a zero-padded decimal number.	01, 02, …, 12
        %p	Locale’s equivalent of either AM or PM.
        AM, PM (en_US);
        am, pm (de_DE)
        (1), (2)
        %M	Minute as a zero-padded decimal number.	00, 01, …, 59
        %S	Second as a zero-padded decimal number.	00, 01, …, 59	(3)
        %f	Microsecond as a decimal number, zero-padded on the left.	000000, 000001, …, 999999	(4)
        %z	UTC offset in the form +HHMM or -HHMM (empty string if the the object is naive).	(empty), +0000, -0400, +1030	(5)
        %Z	Time zone name (empty string if the object is naive).	(empty), UTC, EST, CST
        %j	Day of the year as a zero-padded decimal number.	001, 002, …, 366
        %U	Week number of the year (Sunday as the first day of the week) as a zero padded decimal number. All days in a new year preceding the first Sunday are considered to be in week 0.	00, 01, …, 53	(6)
        %W	Week number of the year (Monday as the first day of the week) as a decimal number. All days in a new year preceding the first Monday are considered to be in week 0.	00, 01, …, 53	(6)
        %c	Locale’s appropriate date and time representation.
        Tue Aug 16 21:30:00 1988 (en_US);
        Di 16 Aug 21:30:00 1988 (de_DE)
        (1)
        %x	Locale’s appropriate date representation.
        08/16/88 (None);
        08/16/1988 (en_US);
        16.08.1988 (de_DE)
        (1)
        %X	Locale’s appropriate time representation.
        21:30:00 (en_US);
        21:30:00 (de_DE)
        (1)
        %%	A literal '%' character.	%
        :param attr_name:
        :param value:
        :return:
        """
        # todo:
        #from datetime import datetime

        #datetime_object = datetime.strptime('Jun 1 2005  1:33PM', '%b %d %Y %I:%M%p')
        print("# todo: date string")

    def init_attrs(self, dict_src, dict_options):
        for key_src, value in dict_src.items():
            if key_src not in dict_options:
                for key_src_, value_ in dict_src.items():
                    print("{}  {}".format(key_src_, key_src_ in dict_options))
                #pdb.set_trace()
                raise self.UnknownKeyError("Unknown key: " + key_src)
            dict_options[key_src](key_src, value)

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
    def convert_to_dict_static(obj_src):
        if type(obj_src) in [str, int, bool]:
            return obj_src
        elif type(obj_src) == dict:
            ret = {}
            for key, value in obj_src.items():
                if type(key) not in [int, str]:
                    raise Exception
                ret[key] = AwsObject.convert_to_dict_static(value)
            return ret
        elif type(obj_src) == list:
            return [AwsObject.convert_to_dict_static(value) for value in obj_src]
        elif isinstance(obj_src, AwsObject):
            return obj_src.convert_to_dict()
        else:
            return str(obj_src)

    class UnknownKeyError(Exception):
        pass

import sys
import pdb

sys.path.insert(0, "/Users/alexeybe/private/aws_api/src/base_entities")

from environment import Environment

def test_hash():
    from environments_examples.env_1 import env_1 as dict_src
    env = Environment()
    env.init_from_dict(dict_src)

    env1 = Environment()
    env1.init_from_dict(dict_src)

    dict_tmp = dict()
    dict_tmp[env] = 1
    dict_tmp[env1] = 2

    assert dict_tmp.get(env) == 2

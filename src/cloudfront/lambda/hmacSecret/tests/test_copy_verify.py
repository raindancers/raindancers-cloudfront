"""copy_secret_to_kvs must fail loudly when the key does not land in the KVS (#206)."""
import importlib.util
import json
import os
import sys
import types
import unittest


def _load(boto3_stub):
    sys.modules['boto3'] = boto3_stub
    if 'urllib3' not in sys.modules:
        u = types.ModuleType('urllib3')
        u.PoolManager = lambda *a, **k: None
        sys.modules['urllib3'] = u
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, 'index.py')
    spec = importlib.util.spec_from_file_location('hmac_copy', path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _NotFound(Exception):
    pass


class _KVS:
    """KVS stub. `drop_writes` simulates a put that is accepted but does not stick."""
    def __init__(self, drop_writes=False):
        self.store = {'jwt.secret': 'stale'}
        self.drop_writes = drop_writes
        self.exceptions = types.SimpleNamespace(ResourceNotFoundException=_NotFound)

    def describe_key_value_store(self, KvsARN):
        return {'ETag': 'e'}

    def get_key(self, KvsARN, Key):
        return {'Value': self.store[Key]}

    def put_key(self, KvsARN, Key, Value, IfMatch):
        if not (self.drop_writes and Key == 'jwt.secret'):
            self.store[Key] = Value


def _boto3(kvs):
    sm = types.SimpleNamespace(get_secret_value=lambda SecretId: {'SecretString': json.dumps({'hmac_key': 'fresh'})})
    return types.SimpleNamespace(client=lambda name, *a, **k: sm if name == 'secretsmanager' else kvs)


class CopyVerifyTests(unittest.TestCase):
    def test_copy_lands_and_keeps_the_previous_key(self):
        kvs = _KVS()
        _load(_boto3(kvs)).copy_secret_to_kvs('arn:secret', 'arn:kvs')
        self.assertEqual(kvs.store['jwt.secret'], 'fresh')
        self.assertEqual(kvs.store['jwt.secret.old'], 'stale')

    def test_a_write_that_does_not_stick_raises(self):
        kvs = _KVS(drop_writes=True)
        with self.assertRaises(RuntimeError):
            _load(_boto3(kvs)).copy_secret_to_kvs('arn:secret', 'arn:kvs')


if __name__ == '__main__':
    unittest.main()

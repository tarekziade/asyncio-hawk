import unittest
from asynchawk import Signer
import json
from mohawk.receiver import Receiver


class TestSigner(unittest.TestCase):

    def test_signing(self):
        url = 'http://example.com'
        json_dump = {'a': 1, 'b': 2, 'c': 4}
        signer = Signer(id='SOMEID', key='MYKEY')
        headers, data = signer.sign(url, 'POST',
                    data=json_dump)

        creds = {
            'id': 'SOMEID',
            'key': 'MYKEY',
            'algorithm': 'sha256',
            }

        def creds_map(id):
            if id != 'SOMEID':
                raise TypeError('Unkown id')
            return creds

        ct = headers['Content-Type']
        content = data
        rc = Receiver(creds_map, headers['Authorization'], url, 'POST',
                content=json.dumps(content), content_type=ct)


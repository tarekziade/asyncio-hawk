import binascii
import codecs
import hashlib
import hmac
import math
from six.moves import xrange
from six.moves.urllib.parse import urlparse
from six import text_type

import mohawk




class Signer:
    def __init__(self, hawk_session=None, id=None, key=None, algorithm='sha256',
                 credentials=None, server_url=None, _timestamp=None):
        if credentials is not None:
            raise AttributeError("The 'credentials' param has been removed. "
                                 "Pass 'id' and 'key' instead, or '**credentials_dict'.")

        if (hawk_session and (id or key)
                or not hawk_session and not (id and key)):
            raise AttributeError("You should pass either 'hawk_session' "
                                 "or both 'id' and 'key'.")

        if hawk_session:
            try:
                hawk_session = codecs.decode(hawk_session, 'hex_codec')
            except binascii.Error as e:
                raise TypeError(e)
            keyInfo = 'identity.mozilla.com/picl/v1/sessionToken'
            keyMaterial = HKDF(hawk_session, "", keyInfo, 32*2)
            id = codecs.encode(keyMaterial[:32], "hex_codec")
            key = codecs.encode(keyMaterial[32:64], "hex_codec")

        self.credentials = {
            'id': id,
            'key': key,
            'algorithm': algorithm
        }
        self._timestamp = _timestamp
        self.host = urlparse(server_url).netloc if server_url else None

    async def get(self, url, *args, **kw):
        headers = kw.pop('headers', {})
        if self.host is not None:
            headers['Host'] = self.host

        sender = mohawk.Sender(
            self.credentials,
            url,
            'GET',
            content='',
            content_type=headers.get('Content-Type', ''),
            _timestamp=self._timestamp
        )

        headers['Authorization'] = sender.request_header
        print(headers['Authorization'])
        return (await self._session.get(url, *args, headers=headers,
                **kw))


    def __call__(self, session):
        self._session = session
        return self

        sender = mohawk.Sender(
            self.credentials,
            r.url,
            r.method,
            content=r.body or '',
            content_type=r.headers.get('Content-Type', ''),
            _timestamp=self._timestamp
        )

        r.headers['Authorization'] = sender.request_header
        return r


def HKDF_extract(salt, IKM, hashmod=hashlib.sha256):
    """HKDF-Extract; see RFC-5869 for the details."""
    if salt is None:
        salt = b"\x00" * hashmod().digest_size
    if isinstance(salt, text_type):
        salt = salt.encode("utf-8")
    return hmac.new(salt, IKM, hashmod).digest()


def HKDF_expand(PRK, info, L, hashmod=hashlib.sha256):
    """HKDF-Expand; see RFC-5869 for the details."""
    if isinstance(info, text_type):
        info = info.encode("utf-8")
    digest_size = hashmod().digest_size
    N = int(math.ceil(L * 1.0 / digest_size))
    assert N <= 255
    T = b""
    output = []
    for i in xrange(1, N + 1):
        data = T + info + chr(i).encode("utf-8")
        T = hmac.new(PRK, data, hashmod).digest()
        output.append(T)
    return b"".join(output)[:L]


def HKDF(secret, salt, info, size, hashmod=hashlib.sha256):
    """HKDF-extract-and-expand as a single function."""
    PRK = HKDF_extract(salt, secret, hashmod)
    return HKDF_expand(PRK, info, size, hashmod)

import unittest
import aiohttp
from asynchawk import Signer
from molotov.tests import support


class TestSigning(unittest.TestCase):
    @support.async_test
    async def test_simple_signing(self, loop, **kw):

        signer = Signer(id='SOMEID', key='MYKEY')

        async with aiohttp.ClientSession() as session:
            session = signer(session)
            resp = await session.get('http://example.com')

from __future__ import absolute_import

import hashlib
import io
import platform
import random

import mock
import pytest
import requests.exceptions

from log_archiver import util

try:
    range = xrange
except NameError:
    pass


class TestGetInstanceId(object):
    @staticmethod
    @pytest.yield_fixture
    def mock_get():
        with mock.patch.object(util.requests, 'get') as get:
            yield get

    def test_non_ec2_instance(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError
        assert util.get_instance_id() == platform.uname()[1]

    def test_ec2_instance(self, mock_get):
        instance_id = 'i-25095678'
        mock_get.return_value = mock.Mock(
            spec=[],
            content=instance_id,
            raise_for_status=mock.Mock())
        assert util.get_instance_id() == instance_id


@pytest.mark.parametrize('algorithm', [hashlib.sha1])
@pytest.mark.parametrize('data_length', [0, 1, 128 * 2**10])
def test_hash_stream(algorithm, data_length):
    data = bytearray(random.getrandbits(8) for _ in range(data_length))
    stream = io.BytesIO(data)
    assert util.hash_stream(algorithm, stream) == algorithm(data).digest()

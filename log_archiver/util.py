from __future__ import absolute_import

import platform

import requests
import requests.exceptions

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

EC2_METADATA_ROOT = 'http://instance-data/metadata/'


def get_instance_id():
    metadata_url = urlparse.urljoin(EC2_METADATA_ROOT, 'instance-id')
    try:
        response = requests.get(metadata_url)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException:
        return platform.uname()[1]


def hash_stream(algorithm, stream):
    block_size = 32 * 2**10
    digest = algorithm()
    while True:
        data = stream.read(block_size)
        if not data:
            break
        digest.update(data)
    return digest.digest()

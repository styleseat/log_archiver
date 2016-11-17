from __future__ import absolute_import

import datetime

import mock
import pytest


@pytest.fixture
def mock_datetime_module():
    return mock.Mock(wraps=datetime)


@pytest.fixture
def mock_datetime_class(mock_datetime_module):
    datetime_class = mock.Mock(wraps=datetime.datetime)
    datetime_class.utcnow.return_value = datetime.datetime(2010, 1, 1)
    mock_datetime_module.datetime = datetime_class
    return datetime_class

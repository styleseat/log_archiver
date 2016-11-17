from __future__ import absolute_import

import base64
import copy
import datetime
import fnmatch
import functools
import hashlib
import random
import re
import sys
import uuid

import mock
import pytest
import watchdog.events
import yaml

from log_archiver import archive_logs
from log_archiver.archive_logs import (
    LogEventHandler, S3Archiver, configure_watchers, main)

try:
    range = xrange
except NameError:
    pass


@pytest.fixture
def log_event_handler_pattern():
    return r'.*\Z'


@pytest.fixture
def log_event_handler_action():
    return mock.Mock()


@pytest.fixture
def log_event_handler(log_event_handler_pattern, log_event_handler_action):
    return LogEventHandler(
        re.compile(log_event_handler_pattern), log_event_handler_action)


class TestLogEventHandler(object):
    @staticmethod
    @pytest.fixture
    def path():
        return 'example.log'

    @staticmethod
    @pytest.fixture
    def file_created_event(path):
        return watchdog.events.FileCreatedEvent(path)

    def test_ignores_directory_event(self, log_event_handler, path):
        event = watchdog.events.DirModifiedEvent(path)
        log_event_handler.dispatch(event)
        assert not log_event_handler.action.called

    def test_ignores_file_deleted_event(self, log_event_handler, path):
        event = watchdog.events.FileDeletedEvent(path)
        log_event_handler.dispatch(event)
        assert not log_event_handler.action.called

    def test_handles_file_created_event(
            self, log_event_handler, file_created_event, path):
        log_event_handler.dispatch(file_created_event)
        log_event_handler.action.assert_called_once_with(path)

    def test_handles_file_moved_event(self, log_event_handler, path):
        event = watchdog.events.FileMovedEvent('.'.join((path, 'old')), path)
        log_event_handler.dispatch(event)
        log_event_handler.action.assert_called_once_with(path)

    def test_handles_file_modified_event(self, log_event_handler, path):
        event = watchdog.events.FileModifiedEvent(path)
        log_event_handler.dispatch(event)
        log_event_handler.action.assert_called_once_with(path)

    @pytest.mark.parametrize('log_event_handler_pattern', [r'no-match'])
    def test_event_target_does_not_match_pattern(
            self, log_event_handler, file_created_event):
        log_event_handler.dispatch(file_created_event)
        assert not log_event_handler.action.called

    def test_action_throws(self, log_event_handler, file_created_event):
        log_event_handler.action.side_effect = RuntimeError
        log_event_handler.dispatch(file_created_event)
        assert log_event_handler.action.called


class TestS3Archiver(object):
    @staticmethod
    @pytest.fixture
    def dest_url():
        return 's3://bucket'

    @staticmethod
    @pytest.fixture
    def log_name():
        return 'events'

    @staticmethod
    @pytest.fixture
    def filename_format():
        return '{log_name}-{timestamp}-{fingerprint}.log'

    @staticmethod
    @pytest.fixture
    def dest_options():
        return None

    @staticmethod
    @pytest.fixture
    def fingerprint_method():
        return S3Archiver.FINGERPRINT_DATA

    @staticmethod
    @pytest.fixture
    def archiver_factory(
            dest_url, log_name, filename_format, dest_options,
            fingerprint_method):
        return functools.partial(
            S3Archiver, dest_url, log_name, filename_format,
            dest_options=dest_options,
            fingerprint_method=fingerprint_method)

    @staticmethod
    @pytest.fixture
    def archiver(archiver_factory):
        return archiver_factory()

    @staticmethod
    @pytest.fixture
    def log_path(tmpdir):
        return tmpdir / 'example.log'

    @staticmethod
    @pytest.fixture
    def log_data():
        return bytearray(random.getrandbits(8) for _ in range(32))

    @staticmethod
    @pytest.fixture
    def fingerprint(fingerprint_method, log_path, log_data):
        if fingerprint_method == S3Archiver.FINGERPRINT_DATA:
            fingerprint_data = log_data
        else:
            fingerprint_data = log_path.basename.encode('utf-8')
        print('Fingerprint data: %s' % (fingerprint_data,))
        return base64.urlsafe_b64encode(
            hashlib.sha1(fingerprint_data).digest()).rstrip(b'=')

    @staticmethod
    @pytest.yield_fixture
    def mock_boto():
        with mock.patch.object(archive_logs, 'boto3', autospec=True) as boto:
            yield boto

    @staticmethod
    @pytest.yield_fixture
    def patched_datetime_class(mock_datetime_module, mock_datetime_class):
        with mock.patch.object(archive_logs, 'datetime', mock_datetime_module):
            yield mock_datetime_class

    @pytest.mark.parametrize('dest_url', [
        # unsupported scheme
        'some/path',
        # missing bucket
        's3://',
    ])
    def test_init_dest_url_is_invalid(self, archiver_factory, dest_url):
        with pytest.raises(ValueError):
            archiver_factory()

    @pytest.mark.parametrize('dest_url, bucket, path_prefix', [
        # bucket without trailing slash
        ('s3://bucket', 'bucket', ''),
        # bucket with trailing slash
        ('s3://bucket/', 'bucket', ''),
        # path without trailing slash
        ('s3://bucket/path', 'bucket', 'path/'),
        # path with trailing slash
        ('s3://bucket/path/', 'bucket', 'path/'),
        # nested path
        ('s3://bucket/nested/path', 'bucket', 'nested/path/'),
    ])
    def test_init_dest_url_is_valid(
            self, archiver_factory, dest_url, filename_format, bucket,
            path_prefix):
        archiver = archiver_factory()
        assert archiver.bucket == bucket
        assert archiver.path_prefix == path_prefix
        assert archiver.filename_format == filename_format

    @pytest.mark.parametrize('dest_options, expected_s3_options', [
        # empty
        (
            {},
            {'region': None},
        ),
        # region
        (
            {'region': 'us-east-1'},
            {'region': 'us-east-1'},
        ),
        # kms key
        (
            {'sse-kms-key-id': 'a-key'},
            {
                'region': None,
                'extra_args': {
                    'ServerSideEncryption': 'aws:kms',
                    'SSEKMSKeyId': 'a-key',
                },
            }
        ),
    ])
    def test_init_dest_options_are_not_none(
            self, archiver_factory, dest_options, expected_s3_options):
        archiver = archiver_factory()
        assert archiver.s3_options == expected_s3_options

    @pytest.mark.parametrize('fingerprint_method', ['invalid'])
    def test_init_fingerprint_method_is_invalid(
            self, archiver_factory, fingerprint_method):
        with pytest.raises(ValueError):
            archiver_factory()

    @pytest.mark.parametrize('fingerprint_method', [
        S3Archiver.FINGERPRINT_DATA,
        S3Archiver.FINGERPRINT_NAME,
    ])
    def test_init_fingerprint_method_is_valid(
            self, archiver_factory, fingerprint_method):
        archiver = archiver_factory()
        assert archiver.fingerprint_method == fingerprint_method

    @pytest.mark.parametrize('fingerprint_method', [
        S3Archiver.FINGERPRINT_DATA,
        S3Archiver.FINGERPRINT_NAME,
    ])
    def test_call(
            self, archiver, log_name, filename_format, fingerprint_method,
            log_path, log_data, fingerprint, mock_boto,
            patched_datetime_class):
        region = 'us-west-1'
        extra_args = dict(sse='aws:kms')
        archiver.s3_options = dict(
            region=region,
            extra_args=copy.deepcopy(extra_args))
        log_path.write_binary(log_data)
        metadata = {
            'source-last-modified': datetime.datetime.utcfromtimestamp(
                log_path.mtime()).isoformat(),
            'sha512': base64.urlsafe_b64encode(
                hashlib.sha512(log_data).digest()),
        }
        patched_datetime_class.utcnow.return_value = datetime.datetime(
            2011, 1, 2, 3, 4, 5)
        filename = filename_format.format(
            log_name=log_name,
            timestamp='20110102030405',
            fingerprint=fingerprint)
        key = archiver.path_prefix + '/'.join((
            log_name,
            '2011',
            '01',
            '02',
            filename))
        s3_object = mock.Mock()
        mock_boto.resource.return_value = mock.Mock(Object=s3_object)
        archiver(str(log_path))
        mock_boto.resource.assert_called_once_with('s3', region_name=region)
        s3_object.assert_called_once_with(archiver.bucket, key)
        s3_object.return_value.upload_file.assert_called_once_with(
            str(log_path), ExtraArgs=dict(extra_args, Metadata=metadata))
        assert not log_path.check()


class TestConfigureWatchers(object):
    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def mock_get_instance_id():
        with mock.patch.object(
                archive_logs, 'get_instance_id', autospec=True,
                return_value=str(uuid.uuid4())) as get:
            yield get

    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def mock_observer():
        with mock.patch.object(
                watchdog.observers, 'Observer', autospec=True) as observer:
            yield observer

    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def mock_archiver():
        fingerprint_attrs = {}
        for method in ('NAME', 'DATA'):
            attr = '_'.join(('FINGERPRINT', method))
            fingerprint_attrs[attr] = getattr(archive_logs.S3Archiver, attr)
        with mock.patch.object(
                archive_logs, 'S3Archiver',
                spec=archive_logs.S3Archiver,
                side_effect=lambda *args, **kwargs: mock.Mock(
                    args=args, kwargs=kwargs),
                **fingerprint_attrs) as archiver:
            yield archiver

    @staticmethod
    @pytest.fixture
    def filename_format(mock_get_instance_id):
        return '_'.join((
            '{log_name}',
            '{timestamp}',
            mock_get_instance_id.return_value,
            '{fingerprint}'))

    @staticmethod
    @pytest.fixture
    def log_factory():
        def factory(**kwargs):
            if 'src' not in kwargs:
                kwargs['src'] = '/var/log/%s' % str(uuid.uuid4())
            if 'dest_url' not in kwargs:
                kwargs['dest_url'] = 's3://%s' % str(uuid.uuid4())
            if 'name' not in kwargs:
                kwargs['name'] = str(uuid.uuid4())
            return kwargs

        return factory

    @staticmethod
    @pytest.fixture
    def assert_handlers_registered(
            mock_observer, mock_archiver, filename_format):
        def assert_handlers_registered_(expected_handlers):
            actual_handlers = []
            observer = mock_observer.return_value
            for args, kwargs in observer.schedule.call_args_list:
                assert kwargs == dict(recursive=False)
                event_handler, dirname = args
                pattern = event_handler.pattern.pattern
                archiver = event_handler.action
                dest_url, log_name, filename_format = archiver.args
                handler_config = dict(
                    dirname=dirname,
                    pattern=pattern,
                    dest_url=dest_url,
                    log_name=log_name,
                    filename_format=filename_format)
                handler_config.update(archiver.kwargs)
                actual_handlers.append(handler_config)
            assert actual_handlers == expected_handlers

        return assert_handlers_registered_

    @pytest.mark.parametrize('src', [
        # no dirname
        'a',
        # no basename
        'a/'
    ])
    def test_malformed_log_source(self, log_factory, src):
        with pytest.raises(ValueError):
            configure_watchers(dict(logs=[log_factory(src=src)]))

    def test_s3_option_merging(self, mock_archiver, log_factory):
        default_options = {
            'keep': 'keep-default',
            'overwrite': 'overwrite-default',
        }
        log_options = {
            'overwrite': 'overwrite-instance',
            'new': 'new-instance',
        }
        merged_options = {
            'keep': 'keep-default',
            'overwrite': 'overwrite-instance',
            'new': 'new-instance',
        }
        config = dict(
            s3=default_options,
            logs=[dict(log_factory(), dest_options=log_options)])
        original_config = copy.deepcopy(config)
        configure_watchers(config)
        assert mock_archiver.call_count == 1
        args, kwargs = mock_archiver.call_args
        assert kwargs['dest_options'] == merged_options
        assert original_config == config

    @pytest.mark.parametrize('logs, expected_handlers', [
        # minimal log config
        (
            [
                dict(
                    src='/log/*.log',
                    dest_url='s3://bucket',
                    name='events')],
            [
                dict(
                    dirname='/log',
                    pattern='*.log',
                    dest_options={},
                    fingerprint_method=S3Archiver.FINGERPRINT_DATA)],
        ),
        # maximal log config
        (
            [
                dict(
                    src='/log/*.log',
                    dest_url='s3://bucket',
                    name='events',
                    dest_options={'region': 'us-west-1'},
                    fingerprint=S3Archiver.FINGERPRINT_NAME)],
            [
                dict(
                    dirname='/log',
                    pattern='*.log',
                    dest_options={'region': 'us-west-1'},
                    fingerprint_method=S3Archiver.FINGERPRINT_NAME)],
        ),
        # multiple logs
        (
            [
                dict(
                    src='/log/src1/*.log',
                    dest_url='s3://bucket1',
                    name='src1'),
                dict(
                    src='/log/src2/*.log',
                    dest_url='s3://bucket2',
                    name='src2')],
            [
                dict(
                    dirname='/log/src1',
                    pattern='*.log',
                    dest_options={},
                    fingerprint_method=S3Archiver.FINGERPRINT_DATA),
                dict(
                    dirname='/log/src2',
                    pattern='*.log',
                    dest_options={},
                    fingerprint_method=S3Archiver.FINGERPRINT_DATA)],
        ),
    ])
    def test_logs(
            self, mock_observer, filename_format, assert_handlers_registered,
            logs, expected_handlers):
        for i, handler in enumerate(expected_handlers):
            log = logs[i]
            handler['dest_url'] = log['dest_url']
            handler['log_name'] = log['name']
            handler['filename_format'] = filename_format
            handler['pattern'] = fnmatch.translate(handler['pattern'])
        config = dict(logs=logs)
        observer = configure_watchers(config)
        assert observer == mock_observer.return_value
        assert_handlers_registered(expected_handlers)


class TestMain(object):
    @staticmethod
    @pytest.fixture
    def config():
        return dict(logs=[])

    @staticmethod
    @pytest.fixture
    def config_path(tmpdir):
        return tmpdir / 'config.yml'

    @staticmethod
    @pytest.fixture(autouse=True)
    def config_file(config_path, config):
        config_path.write(yaml.dump(config))

    @staticmethod
    @pytest.fixture
    def args(config_path):
        return ['--config', str(config_path)]

    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def mock_time():
        with mock.patch.object(archive_logs, 'time') as time:
            time.sleep.side_effect = KeyboardInterrupt
            yield time

    @staticmethod
    @pytest.yield_fixture
    def mock_configure_watchers():
        with mock.patch.object(archive_logs, 'configure_watchers') as cfg:
            yield cfg

    def test_args_from_param(self, args, config, mock_configure_watchers):
        main(args=args)
        mock_configure_watchers.assert_called_once_with(config)

    def test_args_from_argv(self, args, config, mock_configure_watchers):
        with mock.patch.object(sys, 'argv', ['archive_logs'] + args):
            main()
        mock_configure_watchers.assert_called_once_with(config)

    def test_observer_integration(self, args):
        main(args=args)

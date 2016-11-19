from __future__ import absolute_import

import argparse
import base64
import copy
import datetime
import fnmatch
import functools
import gzip
import hashlib
import io
import os
import random
import re
import sys
import tempfile
import uuid

import mock
import py.path
import pytest
import watchdog.events
import watchdog.observers.api
import yaml

from log_archiver import archive_logs
from log_archiver.archive_logs import (
    LogEventHandler, S3Archiver, configure_watchers, gzip_file, main,
    process_observed_files, time_interval)

try:
    range = xrange
except NameError:
    pass


def iter_random_bytes(n):
    return (random.getrandbits(8) for _ in range(n))


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
    def file_path(tmpdir):
        path = tmpdir / 'example.log'
        path.write('')
        return str(path)

    @staticmethod
    @pytest.fixture
    def link_path(file_path):
        path = py.path.local('.'.join((file_path, 'lnk')))
        path.mksymlinkto(file_path)
        return str(path)

    @staticmethod
    @pytest.fixture(params=['file_path'])
    def file_created_event(request):
        path = request.getfuncargvalue(request.param)
        return watchdog.events.FileCreatedEvent(path)

    def test_ignores_directory_event(self, log_event_handler, file_path):
        event = watchdog.events.DirModifiedEvent(file_path)
        log_event_handler.dispatch(event)
        assert not log_event_handler.action.called

    def test_ignores_file_deleted_event(self, log_event_handler, file_path):
        event = watchdog.events.FileDeletedEvent(file_path)
        log_event_handler.dispatch(event)
        assert not log_event_handler.action.called

    def test_handles_file_created_event(
            self, log_event_handler, file_created_event, file_path):
        log_event_handler.dispatch(file_created_event)
        log_event_handler.action.assert_called_once_with(file_path)

    def test_handles_file_moved_event(self, log_event_handler, file_path):
        event = watchdog.events.FileMovedEvent(
            '.'.join((file_path, 'old')), file_path)
        log_event_handler.dispatch(event)
        log_event_handler.action.assert_called_once_with(file_path)

    def test_handles_file_modified_event(self, log_event_handler, file_path):
        event = watchdog.events.FileModifiedEvent(file_path)
        log_event_handler.dispatch(event)
        log_event_handler.action.assert_called_once_with(file_path)

    @pytest.mark.parametrize('log_event_handler_pattern', [r'no-match'])
    def test_event_target_does_not_match_pattern(
            self, log_event_handler, file_created_event):
        log_event_handler.dispatch(file_created_event)
        assert not log_event_handler.action.called

    @pytest.mark.parametrize(
        'file_created_event', ['link_path'], indirect=True)
    def test_event_target_is_a_link(
            self, log_event_handler, file_created_event):
        log_event_handler.dispatch(file_created_event)
        assert not log_event_handler.action.called

    def test_event_target_does_not_exist(
            self, log_event_handler, file_created_event):
        os.unlink(file_created_event.src_path)
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
    def archiver_factory(dest_url, log_name, filename_format):
        def factory(**kwargs):
            return S3Archiver(
                dest_url, log_name, filename_format, **kwargs)

        return factory

    @staticmethod
    @pytest.fixture
    def log_path(tmpdir):
        return tmpdir / 'example.log'

    @staticmethod
    @pytest.fixture
    def log_data():
        return bytearray(iter_random_bytes(32))

    @staticmethod
    @pytest.fixture
    def compressor():
        def compress(data):
            compressed = io.BytesIO()
            with gzip.GzipFile(fileobj=compressed, mode='wb') as gz:
                gz.write(bytes(data))
            return compressed.getvalue()

        return compress

    @staticmethod
    @pytest.fixture
    def fingerprint(fingerprint_method, log_path, log_data):
        if fingerprint_method == S3Archiver.FINGERPRINT_DATA:
            fingerprint_data = log_data
        else:
            fingerprint_data = log_path.basename.encode('utf-8')
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

    def test_init_minimal_params(
            self, archiver_factory, dest_url, log_name, filename_format):
        archiver = archiver_factory()
        assert isinstance(archiver.bucket, type(''))
        assert archiver.path_prefix == ''
        assert archiver.log_name == log_name
        assert archiver.filename_format == filename_format
        assert archiver.fingerprint_method == S3Archiver.FINGERPRINT_DATA
        assert archiver.compress is False
        assert archiver.s3_options == {'region': None}

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
        archiver = archiver_factory(dest_options=dest_options)
        assert archiver.s3_options == expected_s3_options

    @pytest.mark.parametrize('fingerprint_method', ['invalid'])
    def test_init_fingerprint_method_is_invalid(
            self, archiver_factory, fingerprint_method):
        with pytest.raises(ValueError):
            archiver_factory(fingerprint_method=fingerprint_method)

    @pytest.mark.parametrize('fingerprint_method', [
        S3Archiver.FINGERPRINT_DATA,
        S3Archiver.FINGERPRINT_NAME,
    ])
    def test_init_fingerprint_method_is_valid(
            self, archiver_factory, fingerprint_method):
        archiver = archiver_factory(fingerprint_method=fingerprint_method)
        assert archiver.fingerprint_method == fingerprint_method

    def test_init_compress_enabled(self, archiver_factory):
        archiver = archiver_factory(compress=True)
        assert archiver.compress is True

    @pytest.mark.parametrize('fingerprint_method', [
        S3Archiver.FINGERPRINT_DATA,
        S3Archiver.FINGERPRINT_NAME,
    ])
    @pytest.mark.parametrize('compress', [False, True])
    def test_call(
            self, archiver_factory, log_name, filename_format,
            fingerprint_method, compress, log_path, log_data, fingerprint,
            compressor, mock_boto, patched_datetime_class):
        region = 'us-west-1'
        extra_args = dict(sse='aws:kms')
        archiver = archiver_factory(
            fingerprint_method=fingerprint_method,
            compress=compress)
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
        if compress:
            filename += '.gz'
        key = archiver.path_prefix + '/'.join((
            log_name,
            '2011',
            '01',
            '02',
            filename))
        s3_object = mock.Mock(
            spec=['bucket_name', 'key', 'upload_fileobj'])
        s3_object_class = mock.Mock(return_value=s3_object)
        mock_boto.resource.return_value = mock.Mock(Object=s3_object_class)
        uploaded_data = bytearray()

        def upload_fileobj(fileobj, **kwargs):
            uploaded_data.extend(fileobj.read())

        s3_object.upload_fileobj.side_effect = upload_fileobj

        archiver(str(log_path))

        mock_boto.resource.assert_called_once_with(
            's3',
            region_name=region,
            config=mock.ANY)
        s3_object_class.assert_called_once_with(archiver.bucket, key)
        s3_object.upload_fileobj.assert_called_once_with(
            mock.ANY, ExtraArgs=dict(extra_args, Metadata=metadata))
        expected_payload = compressor(log_data) if compress else log_data
        assert uploaded_data == expected_payload
        assert not log_path.check()


class TestGzipFile(object):
    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def override_tempdir(tmpdir):
        with mock.patch.object(tempfile, 'tempdir', str(tmpdir)):
            yield

    @staticmethod
    @pytest.fixture
    def data(request):
        return bytearray(iter_random_bytes(request.param))

    @pytest.mark.parametrize('data', [0, 32, 128, 1024], indirect=True)
    def test_gzip(self, data, tmpdir):
        path = tmpdir / 'uncompressed'
        path.write(data)
        with gzip_file(str(path)) as gzf:
            compressed = gzf.read()
        path.remove()
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode='rb') as gzf:
            uncompressed = gzf.read()
        assert uncompressed == data
        assert tmpdir.listdir() == []


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
            '{fingerprint}.log'))

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
                    dest_options={})],
        ),
        # maximal log config
        (
            [
                dict(
                    src='/log/*.log',
                    dest_url='s3://bucket',
                    name='events',
                    dest_options={'region': 'us-west-1'},
                    fingerprint_method=S3Archiver.FINGERPRINT_NAME,
                    compress=True)],
            [
                dict(
                    dirname='/log',
                    pattern='*.log',
                    dest_options={'region': 'us-west-1'},
                    fingerprint_method=S3Archiver.FINGERPRINT_NAME,
                    compress=True)],
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
                    dest_options={}),
                dict(
                    dirname='/log/src2',
                    pattern='*.log',
                    dest_options={})],
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


class TestProcessObservedFiles(object):
    @staticmethod
    @pytest.fixture
    def watch_path(tmpdir):
        return tmpdir

    @staticmethod
    @pytest.fixture
    def watch_dir(watch_path):
        return str(watch_path)

    @staticmethod
    @pytest.fixture
    def emitter(watch_dir):
        return mock.Mock(
            spec=[],
            watch=mock.Mock(
                spec=[],
                path=watch_dir),
            queue_event=mock.Mock())

    @staticmethod
    @pytest.fixture
    def observer(emitter):
        return mock.Mock(
            spec=[],
            emitters=[emitter])

    def test_empty_watch_dir(self, observer, emitter):
        process_observed_files(observer)
        assert not emitter.queue_event.called

    def test_queues_files(self, watch_path, observer, emitter):
        log_names = ['a.log', 'b.log']
        log_paths = []
        for log_name in log_names:
            log_path = watch_path / log_name
            log_path.write('')
            log_paths.append(log_path)
        process_observed_files(observer)
        expected_queue_calls = [
            mock.call(watchdog.events.FileCreatedEvent(str(p)))
            for p in log_paths]
        assert emitter.queue_event.mock_calls == expected_queue_calls

    def test_skips_directories(self, watch_path, observer, emitter):
        watch_path.mkdir('subdir')
        process_observed_files(observer)
        assert not emitter.queue_event.called


class TestTimeInterval(object):
    @pytest.mark.parametrize('value, expected', [
        (1, 1.0),
        ('1', 1.0),
    ])
    def test_valid(self, value, expected):
        assert time_interval(value) == expected

    @pytest.mark.parametrize('value, expected_reason', [
        (None, 'not a number'),
        ('d', 'not a number'),
        (0, 'not positive'),
    ])
    def test_invalid(self, value, expected_reason):
        with pytest.raises(argparse.ArgumentTypeError) as e:
            time_interval(value)
        assert expected_reason in str(e.value)


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
    @pytest.fixture
    def sweep_interval():
        return None

    @staticmethod
    @pytest.fixture(autouse=True)
    def config_file(config_path, config):
        config_path.write(yaml.dump(config))

    @staticmethod
    @pytest.fixture
    def args(config_path, sweep_interval):
        result = ['--config', str(config_path)]
        if sweep_interval is not None:
            result.extend(['--sweep-interval', str(sweep_interval)])
        return result

    @staticmethod
    @pytest.yield_fixture(autouse=True)
    def mock_sleep():
        with mock.patch.object(archive_logs, 'time', autospec=True) as time:
            sleep = time.sleep
            sleep.side_effect = KeyboardInterrupt
            yield sleep

    @staticmethod
    @pytest.yield_fixture
    def mock_configure_watchers():
        with mock.patch.object(
                archive_logs, 'configure_watchers') as configure_watchers:
            yield configure_watchers

    @staticmethod
    @pytest.yield_fixture
    def mock_process_observed_files():
        with mock.patch.object(
                archive_logs, 'process_observed_files') as process_files:
            yield process_files

    @staticmethod
    @pytest.fixture
    def run_test(
            config, sweep_interval, mock_configure_watchers,
            mock_process_observed_files, mock_sleep):
        def run(expected_sweeps=1, **main_kwargs):
            main(**main_kwargs)
            mock_configure_watchers.assert_called_once_with(config)
            expected_sweep_calls = [
                mock.call(mock_configure_watchers.return_value)
                for _ in range(expected_sweeps)]
            assert (
                mock_process_observed_files.mock_calls == expected_sweep_calls)
            expected_sleep_calls = [
                mock.call(sweep_interval or 3600.0)
                for _ in range(expected_sweeps)]
            assert mock_sleep.mock_calls == expected_sleep_calls

        return run

    def test_args_from_param(self, args, run_test):
        run_test(args=args)

    def test_args_from_argv(self, args, run_test):
        with mock.patch.object(sys, 'argv', ['archive_logs'] + args):
            run_test()

    @pytest.mark.parametrize('sweep_interval', [5])
    def test_sweep_loop(self, args, run_test, mock_sleep):
        mock_sleep.side_effect = [None, KeyboardInterrupt]
        run_test(expected_sweeps=2, args=args)

    def test_observer_integration(self, args):
        main(args=args)

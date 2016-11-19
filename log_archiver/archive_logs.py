from __future__ import absolute_import

import argparse
import base64
import contextlib
import datetime
import fnmatch
import gzip
import hashlib
import logging
import os
import os.path
import re
import shutil
import sys
import tempfile
import textwrap
import time

import boto3
import botocore.client
import watchdog.events
import watchdog.observers
import yaml

from .util import get_instance_id, hash_stream

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

logger = logging.getLogger('archive_logs')


@contextlib.contextmanager
def gzip_file(path):
    with open(path, 'rb') as data, tempfile.TemporaryFile() as compressed:
        with gzip.GzipFile(fileobj=compressed, mode='wb') as compressor:
            shutil.copyfileobj(data, compressor)
        compressed.seek(0)
        yield compressed


class LogEventHandler(watchdog.events.FileSystemEventHandler):
    def __init__(self, pattern, action):
        super(LogEventHandler, self).__init__()
        self.pattern = pattern
        self.action = action

    def on_any_event(self, event):
        if event.is_directory or event.event_type not in (
                watchdog.events.EVENT_TYPE_CREATED,
                watchdog.events.EVENT_TYPE_MOVED,
                watchdog.events.EVENT_TYPE_MODIFIED):
            return
        if event.event_type == watchdog.events.EVENT_TYPE_MOVED:
            path = event.dest_path
        else:
            path = event.src_path
        basename = os.path.basename(path)
        if self.pattern.match(basename):
            try:
                # The target path may no longer exist if it was processed
                # by a preceding event.
                if os.path.lexists(path) and not os.path.islink(path):
                    self.action(path)
            except Exception:
                logger.exception(
                    'Unable to complete action for path: %s', path)


class S3Archiver(object):
    """An archiver which pushes logs to s3."""

    FINGERPRINT_DATA = 'data'
    FINGERPRINT_NAME = 'name'

    def __init__(
            self, dest_url, log_name, filename_format,
            dest_options=None,
            fingerprint_method=FINGERPRINT_DATA,
            compress=False):
        """Initialize an s3 archiver.

        :param str dest_url: The URL of the destination which will store
            logs. Only S3 URLs are supported.
        :param str log_name: The symbolic name of the archive, which will
            be used to construct the names of individual archive files.
            This name need not corresponding to the names of the logs
            subject to archival.
        :param str filename_format: Format string to use for log filenames.
            The filename will be constructed by calling `str.format` with the
            following keyword arguments:
            * log_name: The name of the log, as given by the like-named
            parameter to this method.
            * timestamp: The time of the log's archival.
            * fingerprint: The log's fingerprint.
        :kwarg dict dest_options: Options which control the interaction
            with the destination medium, s3.
        :kwarg str fingerprint_method: The method used to fingerprint the log's
            contents. One of the `FINGERPRINT_DATA` or `FINGERPRINT_NAME`
            members in this class.
        :kwarg bool compress: If `True`, the archive data will be compressed.
        """
        dest = urlparse.urlparse(dest_url)
        if dest.scheme != 's3':
            raise ValueError(
                'Invalid destination (unsupported scheme): %s' % dest_url)
        if not dest.netloc:
            raise ValueError(
                'Invalid destination (missing bucket): %s' % dest_url)
        self.bucket = dest.netloc
        path_prefix = dest.path.lstrip('/')
        if path_prefix and not path_prefix.endswith('/'):
            path_prefix = ''.join((path_prefix, '/'))
        self.path_prefix = path_prefix
        self.s3_options = self._make_s3_options(dest_options or {})
        self.log_name = log_name
        self.filename_format = filename_format
        if fingerprint_method not in (
                self.FINGERPRINT_NAME, self.FINGERPRINT_DATA):
            raise ValueError(
                'Invalid fingerprint method: %s' % (fingerprint_method,))
        self.fingerprint_method = fingerprint_method
        self.compress = compress

    def _make_s3_options(self, options):
        result = dict(
            region=options.get('region', None))
        try:
            kms_key_id = options['sse-kms-key-id']
        except KeyError:
            pass
        else:
            extra_args = result['extra_args'] = {}
            extra_args['ServerSideEncryption'] = 'aws:kms'
            extra_args['SSEKMSKeyId'] = kms_key_id
        return result

    def __call__(self, path):
        metadata = {}
        with open(path, 'rb') as data:
            mtime = os.fstat(data.fileno()).st_mtime
            metadata['source-last-modified'] = \
                datetime.datetime.utcfromtimestamp(mtime).isoformat()
            metadata['sha512'] = base64.urlsafe_b64encode(
                hash_stream(hashlib.sha512, data))
            if self.fingerprint_method == self.FINGERPRINT_DATA:
                data.seek(0)
                fingerprint_data = hash_stream(hashlib.sha1, data)
            else:
                fingerprint_data = hashlib.sha1(
                    os.path.basename(path).encode('utf-8')).digest()
            fingerprint = base64.urlsafe_b64encode(
                fingerprint_data).rstrip(b'=')
        now = datetime.datetime.utcnow()
        filename = self.filename_format.format(
            log_name=self.log_name,
            timestamp=now.strftime('%Y%m%d%H%M%S'),
            fingerprint=fingerprint)
        if self.compress:
            filename = '.'.join((filename, 'gz'))
        key = '/'.join((
            self.log_name,
            now.strftime('%Y'),
            now.strftime('%m'),
            now.strftime('%d'),
            filename))
        s3_options = self.s3_options
        extra_args = dict(Metadata=metadata)
        extra_args.update(s3_options.get('extra_args', {}))
        s3 = boto3.resource(
            's3',
            region_name=s3_options['region'],
            config=botocore.client.Config(signature_version='s3v4'))
        s3_object = s3.Object(self.bucket, ''.join((self.path_prefix, key)))
        logger.info(
            'Archiving %s as s3://%s/%s',
            path, s3_object.bucket_name, s3_object.key)
        prepare_data = gzip_file(path) if self.compress else open(path, 'rb')
        with prepare_data as object_data:
            s3_object.upload_fileobj(
                object_data,
                ExtraArgs=extra_args)
        os.unlink(path)


def configure_watchers(config):
    observer = watchdog.observers.Observer()
    instance_id = get_instance_id()
    default_s3_options = config.get('s3', {})
    for log in config['logs']:
        filename_format = '_'.join((
            '{log_name}',
            '{timestamp}',
            instance_id,
            '{fingerprint}.log'))
        dest_options = dict(default_s3_options)
        dest_options.update(log.get('dest_options') or {})
        archiver_opts = {}
        for opt in ('fingerprint_method', 'compress'):
            try:
                archiver_opts[opt] = log[opt]
            except KeyError:
                pass
        archiver = S3Archiver(
            log['dest_url'],
            log['name'],
            filename_format,
            dest_options=dest_options,
            **archiver_opts)
        dirname, basename = os.path.split(log['src'])
        if not (dirname and basename):
            raise ValueError('Invalid source: %s' % (log['src'],))
        pattern = re.compile(fnmatch.translate(basename))
        event_handler = LogEventHandler(pattern, archiver)
        observer.schedule(event_handler, dirname, recursive=False)
    return observer


def process_observed_files(observer):
    for emitter in observer.emitters:
        watch = emitter.watch
        watch_dir = watch.path
        for entry in os.listdir(watch_dir):
            path = os.path.join(watch_dir, entry)
            if os.path.isfile(path):
                event = watchdog.events.FileCreatedEvent(path)
                emitter.queue_event(event)


def time_interval(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('%s is not a number' % (value,))
    if value < 1:
        raise argparse.ArgumentTypeError('%r is not positive' % (value,))
    return value


def argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Archive logs to s3",
        epilog=textwrap.dedent(
            """
            Configuration format
                The configuration file is a YAML document with the following structure.

                # Default s3 options for all logs, which can be overriden with
                # log-specific options
                # (optional)
                s3:
                  region: (optional) s3 region
                  sse-kms-key-id: (optional) KMS key id used to encrypt objects

                # Logs to archive
                logs:
                  - name: Archive name
                    src: Source pattern for logs; accepts simple shell file globs
                    dest_url: Destination s3 url for archives
                    dest_options: (optional) s3 options for the log;
                                  see s3, above, for a list of options
                    fingerprint_method: (optional) Fingerprint method;
                                        can be one of name|data
                    compress: (optional) true to compress data
                  ...
            """))  # noqa
    parser.add_argument(
        '--config',
        type=argparse.FileType('rb'),
        default='config.yml',
        help="YAML configuration file")
    parser.add_argument(
        '--sweep-interval',
        type=time_interval,
        default=3600.0,
        help="""
        Interval at which the archiver will sweep watched directories,
        attempting to archive logs which previously could not be archived
        """)
    return parser


def main(args=None):
    if args is None:
        args = sys.argv[1:]
    args = argument_parser().parse_args(args)
    with args.config as config_file:
        config = yaml.safe_load(config_file)
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)
    observer = configure_watchers(config)
    observer.start()
    try:
        while True:
            process_observed_files(observer)
            time.sleep(args.sweep_interval)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

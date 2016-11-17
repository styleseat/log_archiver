from __future__ import absolute_import

import argparse
import base64
import datetime
import fnmatch
import hashlib
import logging
import os
import re
import sys
import textwrap
import time

import boto3
import watchdog.events
import watchdog.observers
import yaml

from .util import get_instance_id, hash_stream

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

logger = logging.getLogger('archive_logs')


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
                self.action(path)
            except Exception:
                logger.exception(
                    'Unable to complete action for path: %s' % (path,))


class S3Archiver(object):
    """An archiver which pushes logs to s3."""

    FINGERPRINT_DATA = 'data'
    FINGERPRINT_NAME = 'name'

    def __init__(
            self, dest_url, log_name, filename_format,
            dest_options=None,
            fingerprint_method=FINGERPRINT_DATA):
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
        key = '/'.join((
            self.log_name,
            now.strftime('%Y'),
            now.strftime('%m'),
            now.strftime('%d'),
            filename))
        s3_options = self.s3_options
        extra_args = dict(Metadata=metadata)
        extra_args.update(s3_options.get('extra_args', {}))
        s3 = boto3.resource('s3', region_name=s3_options['region'])
        s3_object = s3.Object(self.bucket, ''.join((self.path_prefix, key)))
        s3_object.upload_file(
            path,
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
            '{fingerprint}'))
        dest_options = dict(default_s3_options)
        dest_options.update(log.get('dest_options') or {})
        archiver = S3Archiver(
            log['dest_url'],
            log['name'],
            filename_format,
            dest_options=dest_options,
            fingerprint_method=log.get(
                'fingerprint', S3Archiver.FINGERPRINT_DATA))
        dirname, basename = os.path.split(log['src'])
        if not (dirname and basename):
            raise ValueError('Invalid source: %s' % (log['src'],))
        pattern = re.compile(fnmatch.translate(basename))
        event_handler = LogEventHandler(pattern, archiver)
        observer.schedule(event_handler, dirname, recursive=False)
    return observer


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
                    fingerprint: (optional) Fingerprint method; can be one of name|data
                  ...
            """))  # noqa
    parser.add_argument(
        '--config',
        type=argparse.FileType('rb'),
        default='config.yml',
        help="YAML configuration file")
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
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
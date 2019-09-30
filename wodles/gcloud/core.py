#!/usr/bin/env python3
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import json
import logging
import os
import socket
import sys

from google.cloud import pubsub_v1


HEADER = '1:Wazuh-GCloud:'
WAZUH_PATH = os.path.join('/var', 'ossec')
WAZUH_QUEUE = os.path.join(WAZUH_PATH, 'queue', 'ossec', 'queue')


def get_script_arguments():
    """Get script arguments."""
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring Google Cloud",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-i', '--project_id', dest='project_id',
                        help='Project ID', required=True)

    parser.add_argument('-s', '--subscription_name', dest='subscription_name',
                        help='Subscription name', required=True)

    parser.add_argument('-c', '--credentials_file', dest='credentials_file',
                        help='Credentials file', required=True)

    parser.add_argument('-m', '--max_messages', dest='max_messages', type=int,
                        help='Number of maximum messages pulled in each iteration',
                        required=False, default=100)

    parser.add_argument('-l', '--log_level', dest='log_level', type=int,
                        help='Log level', required=False, default=1)

    return parser.parse_args()


def check_credentials():
    """Check credentials."""
    try:
        credentials_file = os.environ['GOOGLE_APPLICATION_CREDENTIALS']
    except KeyError as e:
        logging.CRITICAL("Environment variable 'GOOGLE_APPLICATION_CREDENTIALS' not found. Wodle cannot start.")


def set_logger(level: int = 1):
    """Set log level.

    :param level: Log level to be set
    """
    # logger = logging.getLogger('gcloud')

    levels = {0: logging.NOTSET,
              1: logging.DEBUG,
              2: logging.INFO,
              3: logging.WARNING,
              4: logging.ERROR,
              5: logging.CRITICAL,
              }

    logger_format = 'Google Cloud Wodle - %(levelno)s - %(funcName)s: %(message)s'
    logging.basicConfig(filename='gcloud.log', format=logger_format,
                        level=levels.get(level, logging.DEBUG))


def send_msg(msg: bytes):
    """Send an event to the Wazuh queue.

    :param msg: Event to be sent
    """
    json_event = json.dumps(format_msg(msg))
    event = f'{HEADER}{json_event}'
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.connect(WAZUH_QUEUE)
        s.send(event.encode(encoding='utf-8', errors='ignore'))
        s.close()
    except socket.error as e:
        if e.errno == 111:
            logging.critical('Wazuh must be running')
            sys.exit(1)
        else:
            logging.critical(f'Error sending event to Wazuh: {e}')


def format_msg(msg: bytes) -> str:
    """Format a message.

    :param msg: Message to be formatted
    """
    return msg.decode(encoding='utf-8', errors='ignore')


def get_subscriber(project_id: str, subscription_name: str) \
                   -> pubsub_v1.SubscriberClient:
    """Get subscriber."""
    subscriber = pubsub_v1.SubscriberClient()
    subscription_path = subscriber.subscription_path(
        project_id, subscription_name)

    return subscriber
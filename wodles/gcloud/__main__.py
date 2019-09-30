#!/usr/bin/env python3
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import core
import logging

import multiprocessing
import logging
import random
import time

from google.cloud import pubsub_v1


def process_message(ack_id, data):
    """Send a message to Wazuh queue."""
    core.send_msg(data)
    subscriber.acknowledge(subscription_path, [ack_id])


# set logger
logger = logging.getLogger(__name__)
core.set_logger(level=1)

# get script arguments
arguments = core.get_script_arguments()
project_id = arguments.project_id
subscription_name = arguments.subscription_name

# get subscriber
subscriber = pubsub_v1.SubscriberClient()
subscription_path = subscriber.subscription_path(project_id, subscription_name)

NUM_MESSAGES = 30

# The subscriber pulls a specific number of messages.
response = subscriber.pull(subscription_path, max_messages=NUM_MESSAGES,
                           return_immediately=True)

processed_messages = 0
while len(response.received_messages) > 0:
    for message in response.received_messages:
        logger.info(f'Sending message {message.message.data} to Wazuh')
        process_message(message.ack_id, message.message.data)
        processed_messages += 1  # increment processed_messages counter
        logger.info(f'ACK received from {message.message.data}')
    # get more messages
    response = subscriber.pull(subscription_path, max_messages=NUM_MESSAGES,
                               return_immediately=True)
    print(f'longitud de response -> {len(response.received_messages)}')
    print(f"ciclo nuevo!, llevamos -> {processed_messages} mensajes procesados")

print(f'Received and acknowledged {processed_messages} messages. Done.')
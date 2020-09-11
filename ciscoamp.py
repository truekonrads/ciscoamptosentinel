import json
import requests
import datetime
import hashlib
import hmac
import base64
import pika
import ssl
import configargparse
import json
import logging
import argparse
from urllib.parse import urlparse
import os
import pytz
LOGGER = logging.getLogger("CiscoAMPToSentinel")

args = None
local_log = None


class SubmissionExcepton(Exception):
    pass


def generate_log_entry(body):
    j = json.loads(body)
    rec = {}
    rec['timestamp'] = datetime.datetime.fromtimestamp(j['timestamp'], tz=pytz.utc)\
        .isoformat()  # .replace("+00:00","Z")
    rec['Computer'] = j['computer']['hostname']
    rec['event_type'] = j['event_type']
    rec['id'] = j['id']
    if 'severity' in j:
        rec['severity'] = j['severity']
    LOGGER.info(f"Event: {rec},")
    rec['OriginalEvent'] = body.decode('utf8', 'ignore')
    oe_len = len(rec['OriginalEvent'])
    LOGGER.debug(f"OriginalEvent length is {oe_len}")
    if oe_len > 32*1024:
        LOGGER.debug(f"OriginalEvent length is too long {oe_len} vs {32*1024}")
        rec['Error'] = "Raw data message too long, truncating"
        rec['OriginalEvent'] = rec['OriginalEvent'][:(32*1024)-1]
    return rec


def on_message(channel, method_frame, header_frame, body):
    try:
        LOGGER.debug(f"Delivery Tag: {method_frame.delivery_tag}")
        LOGGER.debug(f"Body: {body}")
        if local_log is not None:
            local_log.write(body+os.linesep.encode('utf8'))
        rec = generate_log_entry(body)
        post_data(args.workspace, args.key, json.dumps(
            rec), args.log_type, 'timestamp')
        channel.basic_ack(delivery_tag=method_frame.delivery_tag)
    except Exception as e:
        LOGGER.error(f"{e}")


# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

# Build and send a request to the POST API


def post_data(customer_id, shared_key, body, log_type, timegenerated=None):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + \
        resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    if timegenerated:
        LOGGER.debug(f"Using '{timegenerated}' as the timestamp field")
        headers['time-generated-field'] = timegenerated

    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        LOGGER.debug(
            f"Succesfully submitted data to Log Analytics ({log_type}): {response.status_code}:{response.reason}")
    else:
        msg = f"Unsuccessful post to LA; response code: {response.status_code}:{response.reason}"
        LOGGER.error(msg)
        LOGGER.debug(response.content)
        raise SubmissionExcepton(msg)


LOGGER.setLevel(logging.INFO)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def main():

    # CHANGME: Describe what your program does
    parser = configargparse.ArgumentParser(
        description='CiscoAMP event queue to Log Analytics (Sentinel) data pump')
    parser.add_argument('--debug', "-d", action="store_true",
                        help='Debug level messages')
    parser.add('-c', '--config', is_config_file=True, help='config file path')
    parser.add('--amqp-url', required=True, help='AMQP(S) URL', dest="url")
    parser.add('--queue', required=True, help='AMQP Queue name')
    parser.add('--workspace', required=True, help='Log Analytics workspace ID')
    parser.add('--shared-key', required=True, dest="key",
               help='Log Analytics shared key')
    parser.add('--log-type', default='CiscoAMP',
               help='Log type (custom table name without the "_cl")')
    parser.add('--local-log', help="Local log file to record messages to")
    parser.add("--log-replay",
               help="Replay saved events (new line delimited json)")

    global args
    args = parser.parse_args()
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.log_replay:
        with open(args.log_replay, "rb") as log:
            for l in log:
                rec = generate_log_entry(l)
                post_data(args.workspace, args.key, json.dumps(
                    rec), args.log_type, 'timestamp')
                # post_data(args.workspace, args.key, json.dumps(rec), args.log_type)
        return

    global local_log
    if args.local_log is not None:
        local_log = open(args.local_log, "wb+")

    urlparameters = pika.URLParameters(args.url)
    connection = pika.BlockingConnection(urlparameters)

    url_parsed = urlparse(args.url)
    LOGGER.info(
        f"Sucesfully connected to {url_parsed.scheme}://{url_parsed.hostname}")
    channel = connection.channel()
    channel.queue_declare(args.queue, durable=True, passive=True)
    channel.basic_consume(args.queue, on_message)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt")
    finally:
        LOGGER.info("Shutting down")
        channel.stop_consuming()
        connection.close()


if __name__ == '__main__':
    main()

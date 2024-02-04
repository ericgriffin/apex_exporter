#!/usr/bin/python3

# Prometheus exporter for Neptune Apex aquarium controllers

import argparse
import json
import logging
import requests
import signal
import sys
import time

from prometheus_client import Gauge, start_http_server, Summary


# Create a metric to track time spent and requests made.
REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

# define gauges
apex_system = Gauge("neptune_apex_system", "Neptune Apex System Gauge",
                    ["apex", "ip", "software", "hardware", "serial", "type", "timezone"])
apex_modules = Gauge("neptune_apex_modules", "Neptune Apex Modules", ["apex", "abaddr", "hwtype", "hwrev", "swrev"])
apex_wifistat = Gauge("neptune_apex_nstat", "Neptune Apex Network Status", ["apex", "metric"])
apex_power = Gauge("neptune_apex_power", "Neptune Apex Power Availability", ["apex", "metric"])
apex_input = Gauge("neptune_apex_input", "Neptune Apex Input",  ["apex", "did", "type", "name"])
apex_output_state = Gauge("neptune_apex_output_state", "Neptune Apex Output State", ["apex", "did", "type", "name"])
apex_output_intensity = Gauge("neptune_apex_output_intensity", "Neptune Apex Output Intensity",
                              ["apex", "did", "type", "name"])

outlet_state = {"AON": 1, "AOF": 2, "ON": 3, "OFF": 4}


def signal_handler(sig, frame):
    """
    Signal handler
    :param sig:
    :param frame:
    :return:
    """
    LOG.debug(f'Exiting due to {signal.Signals(sig).name} at {frame}')
    sys.exit(0)


def setup_logger(level=logging.INFO):
    """
    Set up logging formatter and handlers
    :param level: logging level (DEBUG, INFO, WARNING, etc.)
    :return: logger object
    """
    logger = logging.getLogger()
    logger.setLevel(level)
    formatter = logging.Formatter('%(asctime)s  %(name)s  %(levelname)s: %(message)s')

    # file handler
    file_handler = logging.FileHandler('apex_exporter.log')
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    # console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def parse_args():
    """

    :return:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('apex_ip', type=str, metavar='apex_ip', nargs='+',
                        help='list of Neptune Apex Controller IPs or hostnames')
    parser.add_argument('--port', type=int,  default=8000, help='Port on which to expose metrics (default 8000)')
    parser.add_argument('--username', help='Neptune Apex Username')
    parser.add_argument('--password', help='Neptune Apex Password')
    parser.add_argument('--refresh', type=int, default=30, help='Refresh rate (default 30s)')
    parser.add_argument('--loglevel', type=str, default='INFO',
                        help='Logging level (DEBUG, INFO, etc.)')

    return vars(parser.parse_args())


def process_login(apex, username, password):
    """

    :param apex:
    :param username:
    :param password:
    :return:
    """
    data = {'login': username, 'password': password}

    try:
        login = requests.post(f'http://{apex}/rest/login', data=json.dumps(data), verify=False)

    except Exception as e:
        LOG.error(f"Could not connect to Apex {apex}: {e}")
        return False

    try:
        login_status = json.loads(login.text)
        LOG.debug(f"{login_status}")

    except Exception as e:
        LOG.error(f"Login failed to Apex {apex}: {e}")

    else:
        LOG.info(f"Successfully logged into {apex}")
        return dict(login.cookies)

    return False


@REQUEST_TIME.time()
def process_request(apex, _cookies):
    """

    :param apex:
    :param _cookies:
    :return:
    """
    try:
        r = requests.get(f'http://{apex}/rest/status', cookies=_cookies)
        status = json.loads(r.text)

    except Exception as e:
        LOG.error(f"Could not fetch metrics from {apex}: {e}")
        return False

    else:
        LOG.info(f"Fetching metrics from {status['system']['hostname']} ({apex})")

    try:
        # process system info
        apex_system.labels(status["system"]["hostname"], apex, status["system"]["software"],
                           status["system"]["hardware"], status["system"]["serial"], status["system"]["type"],
                           status["system"]["timezone"]).set(float(status["system"]["date"]))

        # process modules info
        for module in status["modules"]:
            apex_modules.labels(status["system"]["hostname"], module["abaddr"], module["hwtype"], module["hwrev"],
                                module["swrev"]).set(bool(module["present"]))

        # process network info
        apex_wifistat.labels(status["system"]["hostname"], "quality").set(status["nstat"]["quality"])
        apex_wifistat.labels(status["system"]["hostname"], "strength").set(status["nstat"]["strength"])

        # process power availability
        apex_power.labels(status["system"]["hostname"], "failed").set(status["power"]["failed"])
        apex_power.labels(status["system"]["hostname"], "restored").set(status["power"]["restored"])
        apex_power.labels(status["system"]["hostname"], "secs_since_failed").set(int(status["system"]["date"]) -
                                                                                 int(status["power"]["failed"]))
        apex_power.labels(status["system"]["hostname"], "secs_since_restored").set(int(status["system"]["date"]) -
                                                                                   int(status["power"]["restored"]))

        # process inputs
        for input in status["inputs"]:
            apex_input.labels(status["system"]["hostname"], input["did"], input["type"],
                              input["name"]).set(float(input["value"]))

        # process outputs
        for output in status["outputs"]:
            if output["status"][0] in outlet_state:
                _outlet_state = outlet_state[output["status"][0]]
            else:
                _outlet_state = 0

            apex_output_state.labels(status["system"]["hostname"], output["did"], output["type"],
                                     output["name"]).set(int(_outlet_state))

            # process variable outputs
            if output["type"] == "variable" or output["type"] == "serial":
                if "intensity" in output:
                    apex_output_intensity.labels(status["system"]["hostname"], output["did"], output["type"],
                                                 output["name"]).set(float(output["intensity"]))
    
    except Exception as e:
        LOG.debug(f"{e}")


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    LOG = setup_logger(args['loglevel'])

    # Start up the web server to expose the metrics.
    try:
        LOG.info(f"Starting HTTP server on port {args['port']}")
        start_http_server(args['port'])

    except Exception as e:
        LOG.critical(f"Could not start HTTP server on port {args['port']}: {e}")
        sys.exit(1)

    else:
        LOG.info(f"HTTP server has started successfully")

    apex_login = dict()

    while True:
        # login to each controller to obtain the login cookies
        for apex in args['apex_ip']:
            apex_login[apex] = process_login(apex, args['username'], args['password'])

        for apex in apex_login.items():
            if apex[1] != 0:
                process_request(apex[0], apex[1])

        time.sleep(args['refresh'])

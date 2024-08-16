#!/usr/bin/env python

import sys
import os
import json
import ipaddress
import requests
from requests.exceptions import ConnectionError, HTTPError
from socket import socket, AF_UNIX, SOCK_DGRAM
import time

# Enable or disable debugging
debug_enabled = True  # Set to False to disable debug logging

# File and socket paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f'{pwd}/queue/sockets/queue'

# Set paths for logging
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = f'{pwd}/logs/integrations.log'

def debug(msg):
    """Log debug messages."""
    if debug_enabled:
        timestamped_msg = f"{now}: {msg}\n"
        print(timestamped_msg)
        with open(log_file, "a") as f:
            f.write(timestamped_msg)

def send_event(msg, agent=None):
    """Send an event to the Wazuh Manager."""
    try:
        if not agent or agent["id"] == "000":
            string = f'1:misp:{json.dumps(msg)}'
        else:
            string = f'1:[{agent["id"]}] ({agent["name"]}) {agent["ip"] if "ip" in agent else "any"}->misp:{json.dumps(msg)}'

        debug(f"Sending Event: {string}")
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(socket_addr)
            sock.send(string.encode())
    except Exception as e:
        debug(f"Error sending event: {e}")

# Read configuration parameters
try:
    alert_file = open(sys.argv[1])
    alert = json.loads(alert_file.read())
    alert_file.close()
    debug("Alert loaded successfully")
except Exception as e:
    debug(f"Error reading alert file: {e}")
    sys.exit(1)

# New Alert Output for MISP Alert or Error calling the API
alert_output = {}

# MISP Server Base URL
misp_base_url = "URL of your MISP Instance"
# MISP Server API AUTH KEY
misp_api_auth_key = "API Key Here"
# API - HTTP Headers
misp_apicall_headers = {
    "Content-Type": "application/json",
    "Authorization": f"{misp_api_auth_key}",
    "Accept": "application/json"
}

# Extract Event Source and Type
try:
    event_source = alert["rule"]["groups"][0]
    debug(f"Event source: {event_source}")
except KeyError as e:
    debug(f"Missing expected key in alert: {e}")
    sys.exit(1)

if event_source == 'web':
    try:
        client_ip = alert["data"]["srcip"]
        debug(f"Extracted Client IP: {client_ip}")

        if ipaddress.ip_address(client_ip).is_global:
            misp_search_value = f"value:{client_ip}"
            misp_search_url = f'{misp_base_url}{misp_search_value}'
            debug(f"MISP API URL: {misp_search_url}")

            try:
                misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
                misp_api_response.raise_for_status()
                debug("API request successful")
            except ConnectionError as conn_err:
                alert_output["misp"] = {"error": 'Connection Error to MISP API'}
                alert_output["integration"] = "misp"
                debug(f"ConnectionError: {conn_err}")
                send_event(alert_output, alert.get("agent"))
            except HTTPError as http_err:
                alert_output["misp"] = {"error": f'HTTP Error: {http_err}'}
                alert_output["integration"] = "misp"
                debug(f"HTTPError: {http_err}")
                send_event(alert_output, alert.get("agent"))
            except Exception as e:
                alert_output["misp"] = {"error": f'Unexpected Error: {e}'}
                alert_output["integration"] = "misp"
                debug(f"Unexpected Error: {e}")
                send_event(alert_output, alert.get("agent"))
            else:
                try:
                    misp_api_response = misp_api_response.json()
                    debug(f"API Response Data: {misp_api_response}")

                    if "Attribute" in misp_api_response["response"] and misp_api_response["response"]["Attribute"]:
                        # Generate Alert Output from MISP Response
                        attribute = misp_api_response["response"]["Attribute"][0]
                        alert_output["misp"] = {
                            "event_id": attribute["event_id"],
                            "category": attribute["category"],
                            "value": attribute["value"],
                            "type": attribute["type"]
                        }
                        alert_output["integration"] = "misp"
                        debug(f"Alert Output: {alert_output}")
                        send_event(alert_output, alert.get("agent"))
                    else:
                        alert_output["misp"] = {"error": 'No Attributes found in MISP response'}
                        alert_output["integration"] = "misp"
                        debug("No Attributes found in MISP response")
                        send_event(alert_output, alert.get("agent"))
                except Exception as e:
                    alert_output["misp"] = {"error": f"Error parsing JSON response: {e}"}
                    alert_output["integration"] = "misp"
                    debug(f"Error parsing JSON response: {e}")
                    send_event(alert_output, alert.get("agent"))
        else:
            debug(f"Client IP is not global: {client_ip}")
            sys.exit()
    except KeyError as e:
        alert_output["misp"] = {"error": f'Missing expected key: {e}'}
        alert_output["integration"] = "misp"
        debug(f"KeyError: {e}")
        send_event(alert_output, alert.get("agent"))
        sys.exit()
else:
    debug(f"Event source is not 'awswaf': {event_source}")
    sys.exit()

import json
import logging
from base64 import b64encode

import requests
import urllib3

from .logger_helper import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger()


class Wazuh:
    def __init__(self, protocol, host, port, login_endpoint, user, password):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.login_endpoint = login_endpoint
        self.user = user
        self.password = password
        self.url = f"{self.protocol}://{self.host}:{self.port}"

    # skipcq: PTC-W6001
    def login(self):
        login_url = f"{self.url}/{self.login_endpoint}"
        basic_auth = f"{self.user}:{self.password}".encode()
        login_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Basic {b64encode(basic_auth).decode()}",
        }
        response = requests.get(login_url, headers=login_headers, verify=False)  # nosec
        token = json.loads(response.content.decode())["data"]["token"]
        requests_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        return requests_headers

    # skipcq: PTC-W6001
    def wazuh_api_info(self, requests_headers):
        response = requests.get(
            f"{self.url}/", headers=requests_headers, verify=False  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]

    # skipcq: PTC-W6001
    def wazuh_get_daemons_stat(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/status",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_base_info(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/info", headers=requests_headers, verify=False  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_configuration(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/configuration",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_validate_configuration(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/configuration/validation",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats?pretty=true",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        try:
            stat_response = response.json()["data"]["affected_items"]
        except KeyError:
            stat_response = {}
        return stat_response

    # skipcq: PTC-W6001
    def wazuh_get_hourly_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/hourly",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]

    # skipcq: PTC-W6001
    def wazuh_get_weekly_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/weekly",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_analysisd_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/analysisd",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_remote_stats(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/stats/remoted",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_logs(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/logs", headers=requests_headers, verify=False  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_logs_summary(self, requests_headers):
        response = requests.get(
            f"{self.url}/manager/logs/summary",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_agent_connection(self, requests_headers):
        response = requests.get(
            f"{self.url}/agents?pretty&offset=0&sort=status",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_agents_overview(self, requests_headers):
        response = requests.get(
            f"{self.url}/overview/agents",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]

    # skipcq: PTC-W6001
    def wazuh_get_nodes_healtchecks(self, requests_headers):
        response = requests.get(
            f"{self.url}/cluster/healthcheck",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
            return None
        else:
            return response.json()["data"]["affected_items"]

    # skipcq: PTC-W6001
    def wazuh_get_last_scan_syscheck(self, requests_headers, agent_id):
        response = requests.get(
            f"{self.url}/syscheck/{agent_id}",
            headers=requests_headers,
            verify=False,  # nosec
        )
        if response.status_code != 200:
            logging.warning(
                f"Got response http code {response.status_code}, response body {response.json()['detail']}"
            )
        return response.json()["data"]["affected_items"]

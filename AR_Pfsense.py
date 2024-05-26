#!/usr/bin/python3

import requests
import urllib3
# Temporarily disabling InsecureRequestWarning due to self-signed certificate
import json
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log(message):
    with open('./ar-log.log', 'w') as f:
        f.writelines(message)


def filter_dictionary(dictionary, filters):
    return [entry for entry in dictionary if all(entry.get(key) == value for key, value in filters.items())]


def pprint_json(data: any):
    return json.dumps(data, indent=4, sort_keys=True)


class PfSenseRule:

    @staticmethod
    def create_default_rule():
        return {
            "type": "pass",
            "interface": "lan",
            "ipprotocol": "inet46",
            "protocol": "tcp/udp",
            "src": "any",
            "srcport": "any",
            "dst": "any",
            "dstport": "any",
            "descr": "Pattern rule",
            "top": True,
            "apply": True
        }

    @staticmethod
    def create_custom_rule(rule):
        # Get default rule
        pattern = PfSenseRule.create_default_rule()

        # Apply custom values
        for key, value in rule.items():
            pattern[key] = value

        return pattern


class PfSenseApi:
    """
        Basic implementation of some of the endpoints provided by the following pfsense-api:
            https://github.com/jaredhendrickson13/pfsense-api

    """

    def __init__(self, domain: str):
        self.schema = f"https://{domain}"

        # Create .env file with the following keys/values
        # XXX_API_USER="xxx"
        # XXX_API_PASS="xxx"
        __user = "admin"
        __pass = "pfsense"

        self.session = requests.Session()
        self.session.auth = (__user, __pass)

    def get_firewall_rules(self):
        full_url = f"{self.schema}/api/v1/firewall/rule"
        response = self.session.get(full_url, verify=False)
        response_json = response.json()

        if response.status_code == 200:
            return response_json
        else:
            return {'error_code': response_json['code']}

    def get_specific_firewall_rules(self, filters):
        rules = self.get_firewall_rules()
        return filter_dictionary(rules, filters)

    def post_firewall_rule(self, rule: any):
        full_url = f"{self.schema}/api/v1/firewall/rule"
        response = self.session.post(full_url, json=rule, verify=False)
        response_json = response.json()

        if response.status_code == 200:
            return response_json
        else:
            return {'error_code': response_json['code']}

    def delete_firewall_rule(self, tracker: str):
        full_url = f"{self.schema}/api/v1/firewall/rule?tracker={tracker}"
        response = self.session.delete(full_url)
        response_json = response.json()

        if response.status_code == 200:
            return response_json
        else:
            return {'error_code': response_json['code']}

    def get_firewall_interfaces(self):
        full_url = f"{self.schema}/api/v1/interface"
        response = self.session.get(full_url)
        response_json = response.json()

        if response.status_code == 200:
            return response_json
        else:
            return {'error_code': response_json['code']}

    def apply(self, asynchronous: bool = True):
        full_url = f"{self.schema}/api/v1/firewall/apply"
        response = self.session.post(full_url, {'async': asynchronous}, verify=False)
        response_json = response.json()

        if response.status_code == 200:
            return response_json
        else:
            return {'error_code': response_json['code']}


def main():
    try:
        new_dict = {
            "type": "block",
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "any",
            "src": sys.argv[1],
            "srcport": "any",
            "dst": "any",
            "dstport": "any",
            "descr": "Rule created by Trend Micro",
            "top": True,
            "apply": True
        }
        new_dict_2 = {
            "type": "block",
            "interface": "lan",
            "ipprotocol": "inet",
            "protocol": "any",
            "src": "any",
            "srcport": "any",
            "dst": sys.argv[1],
            "dstport": "any",
            "descr": "Rule created by Trend Micro",
            "top": True,
            "apply": True
        }
        api = PfSenseApi("192.168.123.1")
        debug = True

        #    print(f"Getting all rules..", end=" ")
        #    get_all_rules_response = api.get_firewall_rules()
        #    print(f"{get_all_rules_response['message']}")
        #    if debug:
        #        pprint_json(get_all_rules_response)

        custom_rule = PfSenseRule.create_custom_rule(new_dict)
        custom_rule_2 = PfSenseRule.create_custom_rule(new_dict_2)

        # print(f"Posting custom rule..", end=" ")
        log(f"Posting custom rule..")
        post_custom_rule_response = api.post_firewall_rule(custom_rule)
        custom_rule_tracker = post_custom_rule_response['data']['tracker']
        post_custom_rule_response_2 = api.post_firewall_rule(custom_rule_2)
        custom_rule_tracker_2 = post_custom_rule_response_2['data']['tracker']
        # print(post_custom_rule_response['message'])
        log(post_custom_rule_response['message'])
        log(post_custom_rule_response_2['message'])

        if debug:
            print(f"Tracker: {custom_rule_tracker}")
            log(pprint_json(post_custom_rule_response))
            log(pprint_json(post_custom_rule_response_2))

        # print(f"Deleting custom_rule..", end=" ")
        # delete_custom_rule_response = api.delete_firewall_rule(custom_rule_tracker)
        # print(delete_custom_rule_response['message'])
        #
        # if debug:
        #     pprint_json(delete_custom_rule_response)

        # print("Committing configuration..", end=" ")
        log("Committing configuration..")
        apply_configuration_response = api.apply(asynchronous=False)
        # print(apply_configuration_response['message'])
        log(apply_configuration_response['message'])

        if debug:
            log(pprint_json(apply_configuration_response))
    except Exception as e:
        log(f"Exception occurred: {e}")


if __name__ == '__main__':
    main()

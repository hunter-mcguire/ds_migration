#!/usr/bin/python3

import logging

import requests
from urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(level=logging.INFO)

'''
This script can be run via cmdline program or via import of AgentMove class.
Below is an overview of what occurs throughout the script, execute_move being the entrypoint function.
- Get policy_id, display_name of supplied computerID/IDs via get_ds_computer function
- Capture the policy/parent objects in case of needing to create in Cloud One via get_ds_policy function
- Check Cloue One to see if policies exist and create if not via policy_handler function
- Use newly create policy and execute move_task via create_move_task function
'''

class AgentMove:
    '''
    Main Class to retain all configuration settings and functions
    '''
    
    def __init__(self, ds_host: str, ds_api_key: str, cloud_region: str,
                 cloud_api_key: str, ds_ssl_verify: bool = True,
                 ds_port: int = 443) -> None:

        self.ds_api_key = ds_api_key
        self.ds_url = f'{ds_host}:{ds_port}/api'
        self.ds_ssl_verify = ds_ssl_verify
        self.cloud_region = cloud_region
        self.cloud_url = f'https://workload.{self.cloud_region}.cloudone.trendmicro.com/api'
        self.cloud_api_key = cloud_api_key
        self.api_version = 'v1'
        self.ds_headers = {
            'api-secret-key': self.ds_api_key,
            'api-version': self.api_version
        }
        self.c1_headers = {
            'Authorization': f'ApiKey {self.cloud_api_key}',
            'api-version': self.api_version
        }

        if not self.ds_ssl_verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    def get_ds_computer(self, computer_id: int) -> tuple:
        '''
        Function to describe computer, returns: (policyID, displayName)
        '''
        response = requests.get(
            url=f'{self.ds_url}/computers/{computer_id}?expand=none',
            headers=self.ds_headers,
            verify=self.ds_ssl_verify
        ).json()
        
        error = response.get('message')
        if error:
            return ('error', error)
        else:
            return response['policyID'], response['displayName']
    
    def get_ds_policy(self, policy_id: int) -> dict:
        '''
        Function to get policy via policy_id. Returns dict from json policy.
        '''
        policy = requests.get(
            url=f'{self.ds_url}/policies/{policy_id}',
            headers=self.ds_headers,
            verify=self.ds_ssl_verify
        ).json()

        return policy

    def c1_policy_check(self, policy_name: str) -> int:
        '''
        Function to check if policy_name exists in Cloud One.
        Returns PolicyID or 0.
        '''
        search_response = requests.post(
                url=f'{self.cloud_url}/policies/search',
                headers=self.c1_headers,
                json={
                    'searchCriteria': [
                            {
                                'fieldName': 'name',
                                'stringTest': 'equal',
                                'stringValue': policy_name
                            }
                        ]
                    }
            )
        response = search_response.json().get('policies')
        if response:
            return response[0].get('ID') 
        else:
            return 0

    def create_c1_policy(self, agent_policy: dict) -> int:
        '''
        Function to create C1 policy from existing DS policy.
        '''
        resp = requests.post(
            url=f'{self.cloud_url}/policies',
            headers=self.c1_headers,
            json=agent_policy
        )

        return resp.json().get('ID')

    def create_move_task(self, computer_id: int, policy_id: int) -> dict:
        '''
        Function to execute move task and add to list
        '''
        payload = {
            'computerID': computer_id,
            'workloadSecurityPolicyID': policy_id
        }
        agent_move = requests.post(
            url=f'{self.ds_url}/computermovetasks',
            headers=self.ds_headers,
            verify=self.ds_ssl_verify,
            json=payload
        )

        return agent_move.json()
    

    def policy_handler(self, policy: dict, parent_id: int = 0) -> int:
        '''
        Function to handle policy dependancies. Ensuring parent/child policies
        exists prior to initiating move task
        '''
        policy_name = policy['name']
        policy_exists = self.c1_policy_check(policy_name)
        if policy_exists:
            if args.verbose:
                logging.info(f'{policy_name} exists in Cloud One. Ready for move.')
            return policy_exists
        if parent_id:
            parent_policy = self.get_ds_policy(parent_id)
            parent_policy_name = parent_policy['name']
            if args.verbose:
                logging.info(f'Policy inherited from {parent_policy_name}, checking exists in Cloud One')
            c1_parent = self.c1_policy_check(parent_policy_name)
            if c1_parent:
                if args.verbose:
                    logging.info(f'{parent_policy_name} exists in Cloud One. Proceeding..')
                new_policy = policy
                new_policy.pop('ID')
                new_policy['parentID'] = c1_parent
                c1_policy_id = self.create_c1_policy(new_policy)
                if c1_policy_id:
                    if args.verbose:
                        logging.info(f'{policy_name} created in Cloud One. Ready for move.')
                    return c1_policy_id
            else:
                parent_policy.pop('ID')
                if args.verbose:
                    logging.info(f'Parent policy {parent_policy_name} not found in Cloud One.')
                parent_id = self.create_c1_policy(parent_policy)
                if parent_id:
                    if args.verbose:
                        logging.info(f'{parent_policy_name} parent policy created.')
                    new_policy = policy
                    new_policy.pop('ID')
                    new_policy['parentID'] = parent_id
                    c1_policy_id = self.create_c1_policy(new_policy)
                    if c1_policy_id:
                        if args.verbose:
                            logging.info(f'{policy_name} created in Cloud One. Ready for move.')
                        return c1_policy_id
        else:
            if args.verbose:
                logging.info(f'Checking if {policy_name} in Cloud One')
            c1_policy_id = self.c1_policy_check(policy['name'])
            if not c1_policy_id:
                if args.verbose:
                    logging.info(f'Policy {policy_name} does not exist, creating..')
                new_policy = policy
                new_policy.pop('ID')
                c1_policy_id = self.create_c1_policy(new_policy)
                if c1_policy_id:
                    if args.verbose:
                        logging.info(f'{policy_name} created in Cloud One. Ready for move.')
                    return c1_policy_id
        return 0

    def execute_move(self, computer_id: int) -> None:
        '''
        Main entrypoint function:
        - Gets computer info
        - Handles policy dependancies
        - Initiates move task 
        '''
        c1_policy_id = 0
        try:
            computer_info = self.get_ds_computer(computer_id)
            if computer_info[0] == 'error':
                logging.error(computer_info[1])
                return
            else:
                agent_policy_id, agent_display_name = computer_info
            policy = self.get_ds_policy(agent_policy_id)
            parent_id = policy.get('parentID')

            c1_policy_id = self.policy_handler(
                policy=policy,
                parent_id=parent_id if parent_id else 0
            )
        except Exception as error:
            move_error = error

        if c1_policy_id:
            if args.verbose:
                logging.info(f'Creating Move Task: {agent_display_name}')
            try:
                move_task = self.create_move_task(computer_id, c1_policy_id)
                if args.verbose:
                    logging.info(f"{agent_display_name} Move ID: {move_task['ID']}")
            except Exception as error:
                move_error = error
        else:
            if args.verbose:
                logging.warning(f'Error: {move_error}')

if __name__ == '__main__':
    '''
    Main function used if running as commandline program.
    '''
    import argparse

    parser = argparse.ArgumentParser(
        prog='AgentMove',
        description='Script to migrate Deep Security Agent to C1'
    )

    parser.add_argument('--ds_api_key', required=True)
    parser.add_argument('--ds_host', required=True)
    parser.add_argument('--ds_port', type=int, default=443, required=False)
    parser.add_argument('--ds_ssl_ignore', action="store_false",
                        help='Disable TLS verification for DS self signed cert')
    parser.add_argument('--verbose', action="store_true",
                        help='Log output of script progress to console')
    parser.add_argument('--cloud_region', required=True)
    parser.add_argument('--cloud_api_key', required=True)
    parser.add_argument('--computer_id', required=False,
                        help='Migrate single DS agent. ex --computer_id 34')
    parser.add_argument('--computer_ids', nargs='+', required=False,
                        help='Migrate multiple DS agents. 1+ IDs with space between. ex.  --computer_ids 32 33')

    args = parser.parse_args()

    agent = AgentMove(
        ds_host=args.ds_host,
        ds_port=args.ds_port,
        ds_api_key=args.ds_api_key,
        ds_ssl_verify=args.ds_ssl_ignore,
        cloud_region=args.cloud_region,
        cloud_api_key=args.cloud_api_key
    )
    if args.computer_ids:
        assert not args.computer_id
        for _id in args.computer_ids:
            agent.execute_move(int(_id))
    else:
        assert not args.computer_ids
        agent.execute_move(int(args.computer_id))

#!/usr/bin/python3

import requests
from urllib3.exceptions import InsecureRequestWarning

'''
This script can be run via cmdline program or via import of AgentMove class.
Below is an overview of what occurs throughout the script, execute_move being the entrypoint function.
- get policy_id, display_name of supplied computerID/IDs :: get_ds_computer function
- capture the policy/parent objects in case of needing to create in C1 :: get_ds_policy function
- check Cloue One to see if policies exist and create if not :: policy_handler function
- Use newly create policy and execute move_task :: create_move_task function
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
        Function to check if policy_name exists in C1.
        Returns True or False based on policy existence.
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

    def create_c1_policy(self, agent_policy: dict):
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
        policy_exists = self.c1_policy_check(policy['name'])
        if policy_exists:
            print('C1 policy exits') # remove
            return policy_exists
        if parent_id:
            parent_policy = self.get_ds_policy(parent_id)
            print('parent attached to policy, checking if in c1') # remove
            c1_parent = self.c1_policy_check(parent_policy['name'])
            if c1_parent:
                print('parent in c1') # remove
                new_policy = policy
                new_policy.pop('ID')
                new_policy['parentID'] = c1_parent
                c1_policy_id = self.create_c1_policy(new_policy)
                if c1_policy_id:
                    print('created and attached to parent') # remove
                    return c1_policy_id
            else:
                parent_policy.pop('ID')
                print('not in c1, trying to create parent policy') # remove
                parent_id = self.create_c1_policy(parent_policy)
                if parent_id:
                    print('parent policy created, now creating main policy') # remove
                    new_policy = policy
                    new_policy.pop('ID')
                    new_policy['parentID'] = parent_id
                    c1_policy_id = self.create_c1_policy(new_policy)
                    if c1_policy_id:
                        print('new policy created') # remove
                        return c1_policy_id
        else:
            print('no parent policy') # remove
            print('checking if in c1') # remove
            c1_policy_id = self.c1_policy_check(policy['name'])
            if not c1_policy_id:
                print('no policy in c1, creating') # remove
                new_policy = policy
                new_policy.pop('ID')
                c1_policy_id = self.create_c1_policy(new_policy)

            return c1_policy_id

    def execute_move(self, computer_id: int) -> None:
        '''
        Main Function that does the following via AgentMove class
        '''
        c1_policy_id = 0
        try:
            agent_policy_id, agent_display_name = self.get_ds_computer(computer_id)
            policy = self.get_ds_policy(agent_policy_id)
            parent_id = policy.get('parentID')

            c1_policy_id = self.policy_handler(
                policy=policy,
                parent_id=parent_id if parent_id else 0
            )
        except Exception as error:
            move_task = {'error': error}

        if c1_policy_id:
            print('policy ready, executing move') # remove
            try:
                move_task = self.create_move_task(computer_id, c1_policy_id)
            except Exception as error:
                move_task = {'error': error}

if __name__ == '__main__':
    '''
    Main function used if running as commandline program.
    '''
    import argparse

    parser = argparse.ArgumentParser(
        prog='AgentMove',
        description='Script to migrate DS Agent to C1'
    )

    parser.add_argument('--ds_api_key', required=True)
    parser.add_argument('--ds_host', required=True)
    parser.add_argument('--ds_port', type=int, default=443, required=False)
    parser.add_argument('--ds_ssl_ignore', action="store_false")
    parser.add_argument('--cloud_region', required=True)
    parser.add_argument('--cloud_api_key', required=True)
    parser.add_argument('--computer_id', required=False)
    parser.add_argument('--computer_ids', nargs='+', required=False)

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

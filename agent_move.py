import requests
from urllib3.exceptions import InsecureRequestWarning


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
        self.move_list = []

        if not self.ds_ssl_verify:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    def get_ds_computer(self, computer_id: int) -> tuple:
        '''
        Function to describe computer, returns: (policyID, displayName)
        '''
        response = requests.get(
            url=f'{self.ds_url}/computers/{computer_id}?expand=none',
            headers=self.ds_headers
        ).json()

        return response['policyID'], response['displayName']
    
    def get_ds_policy(self, policy_id: int) -> dict:
        '''
        Function to get policy via policy_id. Returns dict from json policy.
        '''
        policy = requests.get(
            url=f'{self.ds_url}/policies/{policy_id}',
            headers=self.ds_headers
        ).json()

        response = {
            'parent_id': policy.get('parentID'),
            'policy': policy
        }

        return response

    def c1_policy_check(self, policy_name: str):
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

        return response['ID'] if response else False

    def create_c1_policy(self, agent_policy: dict):
        '''
        Function to create C1 policy from existing DS policy.
        '''
        try:
            new_policy = requests.post(
                url=f'{self.cloud_url}/policies',
                headers=self.c1_headers,
                json=agent_policy
            ).json()

            return new_policy.get('ID')
        except Exception as error:
            print(error)


    def create_move_task(self, computer_id: int, policy_id: int):
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
        self.move_list.append(agent_move)

        return agent_move

    def policy_handler(self, policy: dict, parent_id: int = 0):
        if parent_id:
            parent_policy = self.get_ds_policy(parent_id).get('policy')
            c1_parent_id = self.c1_policy_check(parent_policy['name'])
            if c1_parent_id:
                new_policy = policy
                new_policy.pop('ID')
                new_policy['parentID'] = c1_parent_id
                c1_policy_id = self.create_c1_policy(new_policy)
                if c1_policy_id:
                    return c1_policy_id
            else:
                parent_policy.pop('ID')
                parent_id = self.create_c1_policy(parent_policy)
                if parent_id:
                    new_policy = policy
                    new_policy.pop('ID')
                    new_policy['parentID'] = parent_id
                    c1_policy_id = self.create_c1_policy(new_policy)
                    if c1_policy_id:
                        return c1_policy_id
        else:
            c1_policy_id = self.c1_policy_check(policy['name'])
            if not c1_policy_id:
                new_policy = policy
                new_policy.pop('ID')
                c1_policy_id = self.create_c1_policy(new_policy)

            return c1_policy_id

    def execute_move(self, computer_id: int):
        '''
        Main Function that does the following via AgentMove class:
        - get policy_id, display_name of supplied computerID/IDs
        - capture the policy/parent objects in case of needing to create in C1
        - check Cloue One to see if policies exist
        - if policy non-existent in C1 create policy in C1
        - Use newly create policy and execute move_task
        '''

        agent_policy_id, agent_display_name = self.get_ds_computer(computer_id)
        agent_policy = self.get_ds_policy(agent_policy_id)
        parent_id = agent_policy.get('parent_id')
        policy = agent_policy.get('policy')
        
        if parent_id:
            c1_policy_id = self.policy_handler(parent_id=parent_id,
                                               policy=policy)
            if c1_policy_id:
                print(f'{computer_id} is ready to move....')
                #self.create_move_task(computer_id, c1_policy_id)
        else:
            c1_policy_id = self.policy_handler(policy)
            if c1_policy_id:
                print(f'{computer_id} is ready to move....')
                #self.create_move_task(computer_id, c1_policy_id)

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
    parser.add_argument('--ds_url', required=True)
    parser.add_argument('--ds_port', type=int, default=443)
    parser.add_argument('--ds_ssl_verify', type=bool, default=True)
    parser.add_argument('--cloud_region', required=True)
    parser.add_argument('--cloud_api_key', required=True)
    parser.add_argument('--computer_id', type=int)
    parser.add_argument('--computer_ids', nargs='+')

    args = parser.parse_args()

    agent = AgentMove(
        dsm_host=args.ds_host,
        dsm_port=args.ds_port,
        dsm_api_key=args.ds_api_key,
        ds_ssl_verify=args.ds_ssl_verify,
        cloud_region=args.cloud_region,
        cloud_api_key=args.cloud_api_key
    )

    if args.computer_ids and isinstance(args.computer_ids, list):
        assert args.computer_id is None
        for _id in args.computer_ids:
            assert isinstance(_id, int)
            agent.execute_move(_id)
    else:
        assert isinstance(args.computer_id, int)
        agent.execute_move(args.computer_id)

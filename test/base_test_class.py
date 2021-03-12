import logging
import re
import subprocess
import textwrap
import unittest
from datetime import datetime

import requests
import urllib3
from atlassian import Jira

log = logging.getLogger(__name__)
# logging.basicConfig(level=logging.INFO)
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(funcName)s(): %(message)s', level=logging.INFO)
# log.handlers[0].setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(funcName)s(): %(message)s'))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class BaseTestClass(unittest.TestCase):
    """Uses running Jira https://bitbucket.org/jheger/jira-anonymizinghelper/src/master """

    STD_PASSWORD = '1'
    PYTHON_BINARY = 'python3'

    def setUp(self):
        # tracemalloc.start()
        self.jira_base_url = 'http://localhost:2990/jira'
        r = self.get_jira_serverinfo()
        r.raise_for_status()
        self.jira_serverinfo = r.json()
        # The Jira version in the format "8.14.0".
        self.jira_version = self.jira_serverinfo['version']
        self.initial_delay = 2
        self.regular_delay = 2
        # advanced_mode=True: Return the raw response. Otherwise the API aborts in case of error-status-codes.
        # But I like to control myself when to abort.
        self.jira_admin_session = Jira(
            url=self.jira_base_url,
            username='admin',
            password=self.get_password_for_jira_user('admin'),
            advanced_mode=True)

    def tearDown(self):
        self.jira_admin_session.close()
        pass

    @classmethod
    def execute_anonymizer(cls, cmd):
        cmd = f'{cls.PYTHON_BINARY} ../anonymize_jira_users.py {cmd}'
        log.info(f"execute: {cmd}")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # result contains: result.returncode, result.stderr, result.stdout.
        return result

    @classmethod
    def execute_anonymizer_and_log_output(cls, cmd, out_filepath):
        r = cls.execute_anonymizer(cmd)
        # result r contains: r.returncode, r.stderr, r.stdout.
        decoded_stdout = r.stdout.decode()
        decoded_stderr = r.stderr.decode()
        print(f"r.returncode: {r.returncode}")
        print(f"r.stderr:\n{decoded_stderr}")
        print(f"r.stdout:\n{decoded_stdout}")
        with open(out_filepath, 'w') as f:
            f.write(f"r.returncode: {r.returncode}\n")
            f.write(f"r.stderr:\n{decoded_stderr}")
            f.write(f"r.stdout:\n{decoded_stdout}")
        return r

    @classmethod
    def write_usernames_to_user_list_file(cls, usernames, filepath='./users.cfg'):
        with open(filepath, 'w') as f:
            for username in usernames:
                f.write(f"{username}\n")

    def create_config_file(self, filename='./my-test-config.cfg', jira_user='admin', jira_pass='admin',
                           user_list_file='./users.cfg', new_owner='new_owner'):
        with open(filename, 'w') as f:
            s = f"""
                [DEFAULT]
                jira_base_url = {self.jira_base_url} 
                jira_auth = Basic {jira_user}:{jira_pass}
                user_list_file = {user_list_file}
                new_owner = {new_owner}
                initial_delay = {self.initial_delay}
                regular_delay = {self.regular_delay}        
                """
            f.write(textwrap.dedent(s))

    #
    # Methods supplementing atlassian.Jira
    #

    def get_system_default_languange(self):
        """Get the system defajlt language.
        This is achieved by requesting the Jira startpage without being logged in.
        """
        url = self.jira_base_url + '/secure/Dashboard.jspa'
        r = requests.get(url)
        html = r.text
        # Examples:
        #   1. <meta name="ajs-user-locale" content="en_US">
        #   2. <meta name="ajs-user-locale" content="de_DE">
        results = re.findall('<meta name="ajs-user-locale" content="(.+?)">', html)
        return results[0]

    def get_jira_serverinfo(self):
        rel_url = '/rest/api/2/serverInfo'
        url = self.jira_base_url + rel_url
        r = requests.get(url=url)
        return r

    def is_jiraversion_ge810(self):
        return self.jira_serverinfo['versionNumbers'][0] == 8 and self.jira_serverinfo['versionNumbers'][1] >= 10

    def user_activate(self, user_name):
        data = {'active': 'true', 'name': user_name}
        self.jira_admin_session.user_update(user_name, data)

    def get_predicted_anonymized_usernames(self, user_names):
        """Needs add-on https://bitbucket.org/jheger/jira-anonymizinghelper/src/master."""
        params = []
        for user_name in user_names:
            params.append(('username', user_name))

        r = self.jira_admin_session.get('/rest/anonhelper/latest/applicationuser', params=params,
                                        headers=self.jira_admin_session.default_headers)
        return r

    @classmethod
    def get_password_for_jira_user(cls, user_name):
        if user_name == 'admin':
            return user_name
        else:
            return cls.STD_PASSWORD

    @classmethod
    def create_dir_name_starting_with_datetime(cls, parts):
        return '_'.join([datetime.now().strftime('%Y%m%dT%H%M%S'), *parts])

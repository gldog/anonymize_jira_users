import json
import logging
import re
import subprocess
import unittest
import zipapp
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

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

    PYTHON_BINARY = 'python3'
    ANONYMIZER_NAME = 'anonymize_jira_users'
    PROJECT_KEY_KSP = 10000

    def setUp(self):
        # tracemalloc.start()
        # self.jira_base_url = 'http://localhost:2990/jira'
        # r_serverinfo = self.get_jira_serverinfo()
        # r_serverinfo.raise_for_status()
        # self.jira_serverinfo = r_serverinfo.json()
        # The Jira version in the format "8.14.0".
        # self.jira_version = self.jira_serverinfo['version']

        self.jira_application = JiraApplication(base_url='http://localhost:2990/jira')

        # Defaults for the config.
        self.initial_delay = 2
        self.regular_delay = 2

        # Create a report-dir-name for each tests-run, consisting of a date-string, the Jira version, and the
        # Jira system default language.
        self.out_base_dir_path = \
            'runs/' + self.create_dir_name_starting_with_datetime(
                [self.jira_application.version, self.jira_application.get_system_default_languange()])

    def tearDown(self):
        self.jira_application.admin_session.close()
        pass

    @classmethod
    def execute_anonymizer(cls, cmd):
        zipapp.create_archive(f'../{cls.ANONYMIZER_NAME}')
        cmd = f'{cls.PYTHON_BINARY} ../{cls.ANONYMIZER_NAME}.pyz {cmd}'
        # cmd = f'{cls.PYTHON_BINARY} ../anonymize_jira_users.py {cmd}'
        log.info(f"execute: {cmd}")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # result contains: result.returncode, result.stderr, result.stdout.
        return result

    @classmethod
    def execute_anonymizer_and_log_output(cls, cmd, out_filepath=None):
        r = cls.execute_anonymizer(cmd)
        # result r contains: r.returncode, r.stderr, r.stdout.
        decoded_stdout = r.stdout.decode()
        decoded_stderr = r.stderr.decode()
        print(f"r.returncode: {r.returncode}")
        print(f"r.stderr:\n{decoded_stderr}")
        print(f"r.stdout:\n{decoded_stdout}")
        if out_filepath:
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

    def write_config_file(self, filename='./my-tests-config.cfg', jira_user='admin', jira_pass='admin',
                          user_list_file='./users.cfg', new_owner='new_owner', exclude_groups=None):
        with open(filename, 'w') as f:
            lines = [
                '[DEFAULT]',
                f'jira_base_url = {self.jira_application.base_url}',
                f'jira_auth = Basic {jira_user}:{jira_pass}',
                f'user_list_file = {user_list_file}',
                f'new_owner = {new_owner}',
                f'initial_delay = {self.initial_delay}',
                f'regular_delay = {self.regular_delay}',
                f'loglevel = DEBUG'
            ]

            if exclude_groups:
                lines.append(f'exclude_groups = {exclude_groups[0]}')
                for _, exclude_group in enumerate(exclude_groups, start=1):
                    lines.append(f'  {exclude_group}')
            f.write('\n'.join(lines))

    @classmethod
    def create_dir_name_starting_with_datetime(cls, parts):
        return '_'.join([datetime.now().strftime('%Y%m%dT%H%M%S'), *parts])


@dataclass
class JiraApplication:
    base_url: str = 'http://localhost:2990/jira'
    admin_session: Jira = field(default=None, init=False)
    serverinfo: dict = field(default=None, init=False)
    # The Jira version as string in the format "8.14.0".
    version: str = field(default_factory=list, init=False)
    #  The Jira version as list in the format [8, 14, 0].
    version_numbers: List[int] = field(default=None, init=False)
    # "Kanban Sample Project" KSP
    project_id: int = field(default=10000)
    # "Task"
    issuetype_id: int = field(default=10002)
    # "My-Userpicker"
    userpicker_customfield_id: str = field(default='customfield_10200', init=False)
    std_password: str = field(default='1')

    def __post_init__(self):
        # advanced_mode=True: Return the raw response. Otherwise the API aborts in case of error-status-codes.
        # But I like to control myself when to abort.
        self.admin_session = Jira(url=self.base_url, username='admin', password='admin', advanced_mode=True)
        r = self.get_jira_serverinfo()
        r.raise_for_status()
        self.serverinfo = r.json()
        # The Jira version as string in the format "8.14.0".
        self.version = self.serverinfo['version']
        #  The Jira version as list in the format [8, 14, 0].
        self.version_numbers = self.serverinfo['versionNumbers']
        self.system_default_languange = self.get_system_default_languange()

    def get_jira_serverinfo(self):
        rel_url = '/rest/api/2/serverInfo'
        url = self.base_url + rel_url
        r = requests.get(url=url)
        return r

    def get_system_default_languange(self):
        """Get the system defajlt language.
        This is achieved by requesting the Jira startpage without being logged in.
        """
        url = self.base_url + '/secure/Dashboard.jspa'
        r = requests.get(url)
        html = r.text
        # Examples:
        #   1. <meta name="ajs-user-locale" content="en_US">
        #   2. <meta name="ajs-user-locale" content="de_DE">
        results = re.findall('<meta name="ajs-user-locale" content="(.+?)">', html)
        return results[0]

    def is_jiraversion_ge810(self):
        """Check if Jira-version is greater or equal than 8.10. """
        return self.version_numbers[0] > 8 or self.version_numbers[0] == 8 and self.version_numbers[1] >= 10

    def is_jiraversion_lt810(self):
        """Check if Jira-version is less than 8.10. """
        return self.version_numbers[0] == 8 and self.version_numbers[1] < 10

    def create_user_if_absent(self, username, email=None, display_name=None, password=None, active=True):
        r = self.admin_session.user(username=username)
        if r.status_code == 200:
            is_active = json.loads(r.text)['active']
            if is_active != active:
                r = self.user_activate(username, active)
            # It doesn't matter which return-value is returned, either from .user() or from
            # user_activate().
            return r

        r = self.admin_session.user_create(
            username=username,
            email=email if email else f'{username}@example.com',
            display_name=display_name if display_name else f'User {username}',
            password=password if password else self.get_password_for_jira_user(username), notification=False)
        if r.status_code == 204 and not active:
            r = self.user_activate(username, False)
        # It doesn't matter which return-value is returned, either from .user_create() or from
        # user_activate().
        return r

    def user_activate(self, user_name, active=True):
        data = {'active': active, 'name': user_name}
        r = self.admin_session.user_update(user_name, data)
        return r

    def unassign_all_issues_in_project(self, project_name):
        r_json = self.admin_session.jql('project = "{}"'.format(project_name), 'key')
        for issue_json in r_json['issues']:
            print("key {}".format(issue_json['key']))
            self.admin_session.assign_issue(issue_json['key'])

    # TODO Replace with issue_create() or issue_create_or_update()
    def create_issue(self, json_body, is_raise_for_status=True):
        print("create_issue()")
        url = self.base_url + '/rest/api/2/issue'
        r = self.admin_session.post(url=url, json=json_body)
        if is_raise_for_status:
            r.raise_for_status()
        return r

    # TODO Replace with issue_create_or_update() ?
    def edit_issue(self, issue_key_or_id, json_body, is_raise_for_status=True):
        url = self.base_url + '/rest/api/2/issue/{}'.format(issue_key_or_id)
        r = self.admin_session.put(url=url, headers={'Content-Type': 'application/json'}, data=json_body)
        if is_raise_for_status:
            r.raise_for_status()
        return r

    def edit_issue_set_single_user_picker(self, issue_key_or_id, customfield_id, user_name, is_raise_for_status=True):
        print("edit_issue_set_single_user_picker(), issue_key_or_id {}, customfield_id {}, user_name {}"
              .format(issue_key_or_id, customfield_id, user_name))
        json_body = json.dumps({
            'fields': {
                customfield_id: {'name': user_name}
            }
        })
        r = self.edit_issue(issue_key_or_id, json_body)
        if is_raise_for_status:
            r.raise_for_status()
        return r

    def edit_issue_set_reporter(self, issue_key_or_id, reporter_name, is_raise_for_status=True):
        print("edit_issue_set_reporter(), issue_key_or_id {}, reporter_name {}"
              .format(issue_key_or_id, reporter_name))
        json_body = json.dumps({
            'fields': {
                'reporter': {'name': reporter_name}
            }
        })
        r = self.edit_issue(issue_key_or_id, json_body)
        if is_raise_for_status:
            r.raise_for_status()
        return r

    def create_issue_and_update_userpicker_customfield_by_user(self, user_name):
        """
        Let the user
            1. create an issue. This makes the user the creator (and the reporter).
            2. set them as user in the custom user picker. By this the tests can check if users in user-fields other
                than creator and reporter are anonymized.
            3. set the user 'admin' as reporter. By this, the user can be deleted as they are no longer in either
                field reporter or assignee.
        """
        log.info(user_name)
        jira_user_session = Jira(
            url=self.base_url,
            username=user_name,
            password=self.get_password_for_jira_user(user_name),
            advanced_mode=True)

        issue_summary = f'User {user_name} created this issue'
        # Let the user create an issue. By this the user is the creator and the reporter.
        body = {
            'project': {'id': self.project_id},
            'summary': issue_summary,
            'issuetype': {'id': self.issuetype_id},
            'assignee': {'name': user_name},
            # 'customfield_10200': {'name': user_name}
        }
        r = jira_user_session.create_issue(fields=body, update_history=True)
        r.raise_for_status()
        r_create = r
        issue_key = r.json()['key']
        # Let the user make a change and set the user to the customfield in one step.
        r = jira_user_session.update_issue_field(issue_key, {self.userpicker_customfield_id: {'name': user_name}})
        r.raise_for_status()
        # The permission scheme allows only project-admins changing the reporter.
        r = self.admin_session.update_issue_field(issue_key, {'reporter': {'name': 'admin'}})
        r.raise_for_status()
        jira_user_session.close()
        return r_create

    def get_predicted_anonymized_userdata(self, user_names):
        """Needs add-on https://bitbucket.org/jheger/jira-anonymizinghelper/src/master."""
        params = []
        for user_name in user_names:
            params.append(('username', user_name))

        r = self.admin_session.get('/rest/anonhelper/latest/applicationuser', params=params,
                                   headers=self.admin_session.default_headers)
        return r

    def get_error_msg_missing_user_in_sys_default_lang(self, user_name):
        """
        Get the error-message for GET REST /rest/api/2/user?username=bob in case that user does not exist.

        This error-message depends on the system-default-language.
        """

        # E.g. "The user named 'user9post84' does not exist".
        # Got from 8.7.0. Checked list for completeness in 8.15.0 (but not for the messages itself).
        error_message_missing_user = {
            # Also en_UK
            'en_US': f"The user named '{user_name}' does not exist",
            'cs_CZ': f"Uživatel se jménem '{user_name}' neexistuje",
            'da_DK': f"Brugernavnet '{user_name}' eksisterer ikke",
            'de_DE': f"Der Benutzer namens '{user_name}' existiert nicht",
            'es_ES': f"El usuario con nombre '{user_name}'no existe",
            'et_EE': f"'{user_name}' nimelist kasutajanime pole olemas",
            'fi_FI': f"Käyttäjää nimeltään '{user_name}' ei ole olemassa",
            'fr_FR': f"L'utilisateur '{user_name}' n'existe pas",
            'hu_HU': f"A(z) '{user_name}' nevű felhasználó nem létezik.",
            'is_IS': f"Notandi með nafnið '{user_name}' er ekki til",
            'it_IT': f"L'utente di nome '{user_name}' non esiste",
            'ja_JP': f"ユーザー名 '{user_name}' は存在しません。",
            'ko_KR': f"이름이 '{user_name}'인 사용자가 존재하지 않습니다.",
            'nl_NL': f"De gebruikersnaam '{user_name}' bestaat niet",
            'no_NO': f"Finner ikke brukernavn '{user_name}'",
            'pl_PL': f"Użytkownik o nazwie \"{user_name}\" nie istnieje",
            'pt_BR': f"O usuário com nome '{user_name}' não existe",
            'ro_RO': f"Utilizatorul numit '{user_name}' nu există",
            'ru_RU': f"Пользователь с именем \"{user_name}\" не существует",
            'sk_SK': f"Používateľ s menom '{user_name}' neexistuje.",
            'sv_SE': f"Användaren med namnet '{user_name}' finns inte",
            'zh_CN': f"用户“{user_name}”不存在"
        }
        try:
            return error_message_missing_user[self.system_default_languange]
        except KeyError:
            return error_message_missing_user['en_US']

    def set_project_lead(self, prokect_key, username):
        log.info(f"set_project_lead(), prokect_key {prokect_key}, username {username}")
        url = self.base_url + '/rest/api/2/project/{}'.format(prokect_key)
        body = {
            'lead': username
        }
        r = self.admin_session.put(url, data=json.dumps(body))
        if r.status_code != 200:
            log.error(f"set_project_lead() for prokect_key {prokect_key} and username {username}"
                      f" returned HTTP-status {r.status_code}, expected 200")
        return r

    @classmethod
    def get_password_for_jira_user(cls, user_name):
        if user_name == 'admin':
            return user_name
        else:
            return cls.std_password

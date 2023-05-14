import dataclasses
import itertools
import json
import logging
import os
import pathlib
import re
import subprocess
import unittest
import zipapp
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Any

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

        self.base_test_path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))

        # Create a report-dir-name for each tests-run, consisting of a date-string, the Jira version, and the
        # Jira system default language.
        self.out_base_dir_path = pathlib.Path(self.base_test_path, '..', 'test_runs',
                                              self.create_dir_name_starting_with_datetime(
                                                  [self.jira_application.version,
                                                   self.jira_application.get_system_default_languange()]))

    def tearDown(self):
        self.jira_application.admin_session.close()
        pass

    def execute_anonymizer(self, cmd, is_log_output=False, out_filepath=None):
        path = pathlib.Path(self.base_test_path, '..', self.ANONYMIZER_NAME)
        log.info(f"path: {path}")
        zipapp.create_archive(path)
        cmd = f'{self.PYTHON_BINARY} {path}.pyz {cmd}'
        # OLD: cmd = f'{cls.PYTHON_BINARY} ../anonymize_jira_users.py {cmd}'
        log.info(f"execute: {cmd}")
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # result contains: result.returncode, result.stderr, result.stdout.
        if is_log_output or out_filepath:
            decoded_stdout = r.stdout.decode()
            decoded_stderr = r.stderr.decode()
            if is_log_output:
                log.info(f"r.returncode: {r.returncode}")
                log.info(f"r.stderr:\n{decoded_stderr}")
                log.info(f"r.stdout:\n{decoded_stdout}")
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
        # advanced_mode=True: Return the raw response. Otherwise, the API aborts in case of error-status-codes.
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
        The lang-setting is present in the <meta>-Tag.
        Examples:
            1. <meta name="ajs-user-locale" content="en_US">
            2. <meta name="ajs-user-locale" content="de_DE">

        :return String with the lang-setting in the format 'enUS', 'deDE', ...
        """
        url = self.base_url + '/secure/Dashboard.jspa'
        r = requests.get(url)
        html = r.text
        results = re.findall('<meta name="ajs-user-locale" content="(.+?)">', html)
        return results[0].replace('_', '')

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

    def rename_user_n_times(self, username, display_name, num_renames=None):
        for i in itertools.count(start=1):
            if num_renames is not None and i > num_renames:
                break
            new_display_name = f'{display_name} {i}'
            print(f"Renaming {username} to {new_display_name}")
            self.admin_session.user_update(username=username, data={
                'displayName': new_display_name
            })

    def unassign_all_issues_in_project(self, project_name):
        r_json = self.admin_session.jql('project = "{}"'.format(project_name), 'key')
        for issue_json in r_json['issues']:
            print("key {}".format(issue_json['key']))
            self.admin_session.assign_issue(issue_json['key'])

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
            'enUS': f"The user named '{user_name}' does not exist",
            'csCZ': f"Uživatel se jménem '{user_name}' neexistuje",
            'daDK': f"Brugernavnet '{user_name}' eksisterer ikke",
            'deDE': f"Der Benutzer namens '{user_name}' existiert nicht",
            'esES': f"El usuario con nombre '{user_name}'no existe",
            'etEE': f"'{user_name}' nimelist kasutajanime pole olemas",
            'fiFI': f"Käyttäjää nimeltään '{user_name}' ei ole olemassa",
            'frFR': f"L'utilisateur '{user_name}' n'existe pas",
            'huHU': f"A(z) '{user_name}' nevű felhasználó nem létezik.",
            'isIS': f"Notandi með nafnið '{user_name}' er ekki til",
            'itIT': f"L'utente di nome '{user_name}' non esiste",
            'jaJP': f"ユーザー名 '{user_name}' は存在しません。",
            'koKR': f"이름이 '{user_name}'인 사용자가 존재하지 않습니다.",
            'nlNL': f"De gebruikersnaam '{user_name}' bestaat niet",
            'noNO': f"Finner ikke brukernavn '{user_name}'",
            'plPL': f"Użytkownik o nazwie \"{user_name}\" nie istnieje",
            'ptBR': f"O usuário com nome '{user_name}' não existe",
            'roRO': f"Utilizatorul numit '{user_name}' nu există",
            'ruRU': f"Пользователь с именем \"{user_name}\" не существует",
            'skSK': f"Používateľ s menom '{user_name}' neexistuje.",
            'svSE': f"Användaren med namnet '{user_name}' finns inte",
            'zhCN': f"用户“{user_name}”不存在"
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


@dataclass
class AnonymizedUser:
    name: str = None
    key: str = None
    display_name: str = None
    active: Any = False
    # Since Jira 8.10.
    deleted: Any = False
    filter_error_message: str = ''
    anonymized_user_name: str = None
    anonymized_user_key: str = None
    anonymized_user_display_name: str = None
    action: str = 'anonymized'


@dataclass()
class ExpectedReportGenerator:
    jira_application: JiraApplication
    users: List[AnonymizedUser] = field(default_factory=list)
    overview: dict = None
    report: dict = None

    def add_user(self, anonymized_user):
        """Make a copy of the AnonymizedUser and add it to the list. """
        self.users.append(AnonymizedUser(**dataclasses.asdict(anonymized_user)))
        pass

    def generate(self):
        self.report = {'overview': {}, 'users': self.users}
        user_names = [user.name for user in self.users]
        log.info(f"user_names {user_names}")
        r = self.jira_application.get_predicted_anonymized_userdata(user_names)
        r.raise_for_status()
        predicted_anonymized_userdata = r.json()
        log.info(f"predicted_anonymized_userdata {predicted_anonymized_userdata}")

        for user in self.users:
            if self.jira_application.is_jiraversion_lt810():
                if user.deleted:
                    # In Jira-versions less than 8.10, deleted users could not retrieve by the REST-API. As a
                    # consequence, most of the attributes of the report are None.
                    user.key = None
                    user.display_name = None
                    user.active = None
                    user.validation_has_errors = False
                    # This message comes from Jiras REST API:
                    # user.filter_error_message = f"The user named '{user.user_name}' does not exist"
                    user.filter_error_message = self.jira_application.get_error_msg_missing_user_in_sys_default_lang(
                        user.name)
                    user.anonymized_user_name = ''
                    user.anonymized_user_key = ''
                    user.anonymized_user_display_name = ''
                    user.action = 'skipped'
                # The 'deleted'-attribute was introduced in Jira 8.10. In tests with Jira-version less than 8.10
                # this attribute is always None.
                user.deleted = None

            if not user.filter_error_message:
                paud_for_user = predicted_anonymized_userdata[user.name]

                if self.jira_application.is_jiraversion_lt810() and user.deleted:
                    user.anonymized_user_name = ''
                    user.anonymized_user_key = ''
                    user.anonymized_user_display_name = ''
                else:
                    if user.anonymized_user_name is None:
                        user.anonymized_user_name = 'jirauser{}'.format(paud_for_user['appUserId'])
                    if user.anonymized_user_key is None:
                        user.anonymized_user_key = 'JIRAUSER{}'.format(paud_for_user['appUserId'])
                    if user.anonymized_user_display_name is None:
                        user.anonymized_user_display_name = paud_for_user['anonymizedDisplayName']

        # Generate 'overview':
        self.report['overview'] = self.overview

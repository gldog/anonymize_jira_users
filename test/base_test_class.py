import logging
import re
import subprocess
import textwrap
import unittest
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

    def setUp(self):
        # tracemalloc.start()
        # self.jira_base_url = 'http://localhost:2990/jira'
        # r_serverinfo = self.get_jira_serverinfo()
        # r_serverinfo.raise_for_status()
        # self.jira_serverinfo = r_serverinfo.json()
        # The Jira version in the format "8.14.0".
        # self.jira_version = self.jira_serverinfo['version']

        self.jira_application = JiraApplication(base_url='http://localhost:2990/jira')

        self.initial_delay = 2
        self.regular_delay = 2

    def tearDown(self):
        self.jira_application.admin_session.close()
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
                jira_base_url = {self.jira_application.base_url} 
                jira_auth = Basic {jira_user}:{jira_pass}
                user_list_file = {user_list_file}
                new_owner = {new_owner}
                initial_delay = {self.initial_delay}
                regular_delay = {self.regular_delay}        
                """
            f.write(textwrap.dedent(s))

    @classmethod
    def create_dir_name_starting_with_datetime(cls, parts):
        return '_'.join([datetime.now().strftime('%Y%m%dT%H%M%S'), *parts])


@dataclass
class JiraApplication:
    base_url: str = 'http://localhost:2990/jira'
    admin_session: Any = field(default=None, init=False)
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

    def user_activate(self, user_name, active=True):
        data = {'active': active, 'name': user_name}
        r = self.admin_session.user_update(user_name, data)
        return r

    def get_predicted_anonymized_userdata(self, user_names):
        """Needs add-on https://bitbucket.org/jheger/jira-anonymizinghelper/src/master."""
        params = []
        for user_name in user_names:
            params.append(('username', user_name))

        r = self.admin_session.get('/rest/anonhelper/latest/applicationuser', params=params,
                                   headers=self.admin_session.default_headers)
        return r

    def get_error_msg_missing_user(self, user_name):
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

    @classmethod
    def get_password_for_jira_user(cls, user_name):
        if user_name == 'admin':
            return user_name
        else:
            return cls.std_password

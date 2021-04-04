import dataclasses
import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import List

from deepdiff import DeepDiff

from base_test_class import BaseTestClass, JiraApplication

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdAnonymize(BaseTestClass):

    def setUp(self):
        super(TestCmdAnonymize, self).setUp()

    def tearDown(self):
        super(TestCmdAnonymize, self).tearDown()

        # for user_name in self.usernames_for_user_list_file:
        #    self.user_activate(user_name)

    def test_01(self):
        """
        Setting up this tests is quite speific to this tests, so all set-up stuff is placed here.
        """
        self.is_include_users_from_generated_test_resouces = False

        pathlib.Path(self.out_base_dir_path).mkdir(parents=True)

        self.usernames_for_user_list_file = []

        self.expected_report_generator = ExpectedReportGenerator(self.jira_application)
        self.expected_report_generator.jira_version = self.jira_application.version_numbers
        self.expected_report_generator.error_msg_missing_user = self.jira_application

        # This user might exist. In that case ignore the error.
        r = self.jira_application.admin_session.user_create(
            username='new_owner',
            email='new_owner@example.com',
            display_name='New Owner',
            password=self.jira_application.get_password_for_jira_user('new_owner'),
            notification=False)
        # No r.raise_for_status() as that user might be already existing.

        #
        # Add users to the list of users to be processed (validated or anonymized).
        #
        if self.is_include_users_from_generated_test_resouces:
            #
            # The following user has been created in Jira < 8.4.
            #

            # User with upper- and lower-case chars in name.
            user_name = 'User1Pre84'
            display_name = 'User 1 Pre 84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='User1Pre84',
                               key='user1pre84',
                               display_name=display_name))

            # A user that will be kept an active user.
            user_name = 'User2Pre84'
            display_name = 'User 2 Pre 84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='User2Pre84',
                               key='user2pre84',
                               display_name=display_name,
                               active=True, deleted=False,
                               filter_is_anonymize_approval=False,
                               filter_error_message='Is an active user.',
                               anonymized_user_name='',
                               anonymized_user_key='',
                               anonymized_user_display_name='',
                               action='skipped'))

            # A renamed user.
            user_name = 'User3Pre84_renamed'
            display_name = 'User 3 Pre 84 (renamed)'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='User3Pre84_renamed',
                               key='user3pre84',
                               display_name=display_name))

            # User with only lower-case letter in name.
            user_name = 'user5pre84'
            display_name = 'user5pre84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='user5pre84',
                               key='user5pre84',
                               display_name=display_name))

            # User with only lower-case letter in name, deleted.
            # TODO Create different data for Jira < 8.10
            user_name = 'user9pre84'
            display_name = 'user9pre84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='user9pre84',
                               key='user9pre84',
                               display_name=display_name,
                               deleted=True,
                               anonymized_user_display_name=''))

            # A user with a name (and key) looking like an anonymized user, but isn't anonymized.
            # Jira doesn't anonymize such user-name. And in versions less than 8.10 the user-key neither.
            # But it anonymizes the user display-name.
            user_name = 'JIRAUSER11111'
            display_name = 'JIRAUSER11111'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name='JIRAUSER11111',
                               key='jirauser11111',
                               display_name=display_name,
                               anonymized_user_name='JIRAUSER11111',
                               anonymized_user_key='jirauser11111'))

        #
        # The following user has been created in Jira >= 8.4.
        #

        # User with upper- and lower-case chars in name.
        user_name = 'User1Post84'
        display_name = 'User 1 Post 84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'User2Post84'
        display_name = 'User 2 Post 84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name,
                           active=True, deleted=False,
                           filter_is_anonymize_approval=False,
                           filter_error_message='Is an active user.',
                           anonymized_user_name='',
                           anonymized_user_key='',
                           anonymized_user_display_name='',
                           action='skipped'))

        user_name = 'user5post84'
        display_name = 'user5post84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        # User with only lower-case letter in name; deleted.
        user_name = 'user9post84'
        display_name = 'user9post84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        # In Jira version <8.10, deleted users won't be anonymized, because the REST API won't find them.
        # The user-key is None in this case. But in version >= 8.10 the API do find them.
        # TODO Create different data for Jira < 8.10
        self.expected_report_generator.add_user(
            AnonymizedUser(name='user9post84',
                           key=json.loads(r.text)['key'],
                           display_name=display_name,
                           deleted=True,
                           anonymized_user_display_name=''))

        # A user with a name looking like an anonymized user, but isn't anonymized.
        # Jira doesn't anonymize such user-name. And in versions less than 8.10 the user-key neither.
        # But it anonymizes the user display-name.
        user_name = 'JIRAUSER21111'
        display_name = 'JIRAUSER21111'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name,
                           anonymized_user_display_name='',
                           anonymized_user_name='JIRAUSER21111',
                           anonymized_user_key=json.loads(r.text)['key']))

        # Let each user become an issue-creator.
        for user_name in self.usernames_for_user_list_file:
            r = self.jira_application.create_issue_and_update_userpicker_customfield_by_user(user_name)
            # Un-assign issue in case of users to be deleted. A user can only be deleted if not an assignee.
            if user_name in ['user9pre84', 'user9post84']:
                issue_key = r.json()['key']
                self.jira_application.admin_session.assign_issue(issue=issue_key, assignee=None)

        # Make most users inactive users.
        for user_name in self.usernames_for_user_list_file:
            # Let there be 2 user active.
            if user_name.lower() in ['user2pre84', 'user2post84']:
                continue
            r = self.jira_application.admin_session.user_deactivate(user_name)
            r.raise_for_status()

        self.expected_report_generator.overview = {
            "number_of_users_in_user_list_file": 11,
            "number_of_skipped_users": 2,
            "number_of_anonymized_users": 9,
            "is_background_reindex_triggered": False
        }

        self.expected_report_generator.generate()

        expected_anonymizing_report_json = dataclasses.asdict(self.expected_report_generator)['report']
        log.info("expected_anonymizing_report_json after update:\n"
                 f"{json.dumps(expected_anonymizing_report_json, indent=4)}")

        # The following file is for documenting the tests.
        with open(self.out_base_dir_path + '/predicted_anonymized_userdata.json', 'w') as f:
            f.write(json.dumps(r.json(), indent=4))

        # Delete the following users to tests validation or anonymization of deleted users.
        # Anonymization of deleted users works since Jira 8.10.
        if self.is_include_users_from_generated_test_resouces:
            r = self.jira_application.admin_session.user_remove('user9pre84')
            r.raise_for_status()
        r = self.jira_application.admin_session.user_remove('user9post84')
        r.raise_for_status()

        user_list_file_path = self.out_base_dir_path + '/users.cfg'
        self.write_usernames_to_user_list_file(self.usernames_for_user_list_file, filepath=user_list_file_path)
        self.config_file_path = self.out_base_dir_path + '/my-tests-config.cfg'
        self.write_config_file(filename=self.config_file_path, user_list_file=user_list_file_path)

        out_dir = self.out_base_dir_path + '/anonymize'
        out_logfile = out_dir + '/log.out'
        r = self.execute_anonymizer_and_log_output(f'anonymize -c {self.config_file_path} -o {out_dir}', out_logfile)
        self.assertEqual(0, r.returncode)

        with open(pathlib.Path(out_dir).joinpath('anonymizing_report.json'), 'r') as f:
            got_anonymizing_report_json = json.loads(f.read())

        exclude_regex_paths = [r"root\['users'\]\[\d+\]\['time_(start|finish|duration)'\]"]
        ddiff = DeepDiff(expected_anonymizing_report_json, got_anonymizing_report_json,
                         exclude_regex_paths=exclude_regex_paths)
        self.assertFalse(ddiff)


@dataclass
class AnonymizedUser:
    name: str = None
    key: str = None
    display_name: str = None
    active: bool = False
    # Since Jira 8.10.
    deleted: bool = False
    validation_has_errors: bool = False
    filter_is_anonymize_approval: bool = True
    filter_error_message: str = ''
    anonymized_user_name: str = None
    anonymized_user_key: str = None
    anonymized_user_display_name: str = None
    action: str = 'anonymized'


@dataclass()
class ExpectedReportGenerator:
    jira_application: JiraApplication
    # predicted_anonymized_userdata: dict = None
    overview: dict = None
    users: List[AnonymizedUser] = field(default_factory=list)
    report: dict = None

    def add_user(self, anonymized_user):
        """Make a copy of the AnonymizedUser and add it to the list. """
        self.users.append(AnonymizedUser(**dataclasses.asdict(anonymized_user)))
        pass

    def generate(self):
        self.report = {'overview': self.overview, 'users': self.users}
        user_names = [user.name for user in self.users]
        log.info(f"user_names {user_names}")
        r = self.jira_application.get_predicted_anonymized_userdata(user_names)
        r.raise_for_status()
        predicted_anonymized_userdata = r.json()
        log.info(f"predicted_anonymized_userdata {predicted_anonymized_userdata}")

        for user in self.users:
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

            if self.jira_application.is_jiraversion_lt810():
                if user.deleted:
                    # In Jira-versions less than 8.10, deleted users could not retrieved by the REST-API. As a
                    # consequence, most of the attributes the the report are None.
                    user.key = None
                    user.display_name = None
                    user.active = None
                    user.validation_has_errors = False
                    user.filter_is_anonymize_approval = False
                    # This message comes from Jiras REST API.
                    # user.filter_error_message = f"The user named '{user.user_name}' does not exist"
                    user.filter_error_message = self.jira_application.get_error_msg_missing_user_in_sys_default_lang(
                        user.name)
                    user.anonymized_user_name = ''
                    user.anonymized_user_key = ''
                    user.anonymized_user_display_name = ''
                    user.action = 'skipped'
                # The 'deleted'-attribute was introduce in Jira 8.10. In tests with Jira-version less than 8.10
                # this attribute is always None.
                user.deleted = None

        # Generate 'overview':
        self.overview['number_of_users_in_user_list_file'] = len(self.users)
        self.overview['number_of_skipped_users'] = 0
        self.overview['number_of_anonymized_users'] = 0
        self.overview['is_background_reindex_triggered'] = False
        for user in self.users:
            if user.action == 'anonymized':
                self.overview['number_of_anonymized_users'] += 1
            elif user.action == 'skipped':
                self.overview['number_of_skipped_users'] += 1

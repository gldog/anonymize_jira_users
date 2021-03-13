import dataclasses
import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import List

from atlassian import Jira
from deepdiff import DeepDiff

from base_test_class import BaseTestClass, JiraApplication

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestAnonymizingWithoutIssues(BaseTestClass):

    def setUp(self):
        super(TestAnonymizingWithoutIssues, self).setUp()

    def tearDown(self):
        super(TestAnonymizingWithoutIssues, self).tearDown()

        # for user_name in self.usernames_for_user_list_file:
        #    self.user_activate(user_name)

    def test_01(self):
        """
        Only this single test here.

        Setting up this test is quite speific to this test, so all set-up stuff is placed here.
        """
        self.is_include_users_from_generated_test_resouces = True

        # Create a report-dir for each test-run, consisting of a date-string, the Jira version, and the
        # Jira system default language.
        self.base_dir_name = \
            'runs/' + self.create_dir_name_starting_with_datetime(
                [self.jira_application.version, self.jira_application.get_system_default_languange()])

        pathlib.Path(self.base_dir_name).mkdir(parents=True)

        self.usernames_for_user_list_file = []

        self.expected_report_generator = ExpectedReportGenerator(self.jira_application)
        self.expected_report_generator.jira_version = self.jira_application.version_numbers
        self.expected_report_generator.error_msg_missing_user = self.jira_application

        # This user might exist. In that case ignore the error.
        r = self.jira_application.admin_session.user_create('new_owner', 'new_owner@example.com', 'New Owner',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'new_owner'), notification=False)
        # No r.raise_for_status() as that user might be already existing.

        #
        # Add users to the list of users to be processed (validated or anonymized).
        #
        if self.is_include_users_from_generated_test_resouces:
            #
            # The following user has been created in Jira < 8.4.
            #

            # User with upper- and lower-case chars in name.
            self.usernames_for_user_list_file.append('User1Pre84')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='User1Pre84',
                               user_key='user1pre84',
                               user_display_name='User 1 Pre 84'))

            # A user that will be kept an active user.
            self.usernames_for_user_list_file.append('User2Pre84')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='User2Pre84',
                               user_key='user2pre84',
                               user_display_name='User 2 Pre 84',
                               active=True, deleted=False,
                               filter_is_anonymize_approval=False,
                               filter_error_message='Is an active user.',
                               anonymized_user_name='',
                               anonymized_user_key='',
                               anonymized_user_display_name='',
                               action='skipped'))

            # A renamed user.
            self.usernames_for_user_list_file.append('User3Pre84_renamed')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='User3Pre84_renamed',
                               user_key='user3pre84',
                               user_display_name='User 3 Pre 84 (renamed)'))

            # User with only lower-case letter in name.
            self.usernames_for_user_list_file.append('user5pre84')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='user5pre84',
                               user_key='user5pre84',
                               user_display_name='user5pre84'))

            # User with only lower-case letter in name, deleted.
            # TODO Create different data for Jira < 8.10
            self.usernames_for_user_list_file.append('user9pre84')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='user9pre84',
                               user_key='user9pre84',
                               user_display_name='user9pre84',
                               deleted=True,
                               anonymized_user_display_name=''))

            # A user with a name (and key) looking like an anonymized user, but isn't anonymized.
            # Jira doesn't anonymize such user-name. And in versions less than 8.10 the user-key neither.
            # But it anonymizes the user display-name.
            self.usernames_for_user_list_file.append('JIRAUSER11111')
            self.expected_report_generator.add_user(
                AnonymizedUser(user_name='JIRAUSER11111',
                               user_key='jirauser11111',
                               user_display_name='JIRAUSER11111',
                               anonymized_user_name='JIRAUSER11111',
                               anonymized_user_key='jirauser11111'))

        #
        # The following user has been created in Jira >= 8.4.
        #

        # User with upper- and lower-case chars in name.
        r = self.jira_application.admin_session.user_create('User1Post84', 'User1Post84@example.com', 'User 1 Post 84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'User1Post84'), notification=False)
        r.raise_for_status()
        self.usernames_for_user_list_file.append('User1Post84')
        self.expected_report_generator.add_user(
            AnonymizedUser(user_name='User1Post84',
                           user_key=json.loads(r.text)['key'],
                           user_display_name='User 1 Post 84'))

        # A user that will be kept an active user.
        r = self.jira_application.admin_session.user_create('User2Post84', 'User2Post84@example.com', 'User 2 Post 84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'User2Post84'), notification=False)
        r.raise_for_status()
        self.usernames_for_user_list_file.append('User2Post84')
        self.expected_report_generator.add_user(
            AnonymizedUser(user_name='User2Post84',
                           user_key=json.loads(r.text)['key'],
                           user_display_name='User 2 Post 84',
                           active=True, deleted=False,
                           filter_is_anonymize_approval=False,
                           filter_error_message='Is an active user.',
                           anonymized_user_name='',
                           anonymized_user_key='',
                           anonymized_user_display_name='',
                           action='skipped'))

        # User with only lower-case letters in name.
        r = self.jira_application.admin_session.user_create('user5post84', 'user5post84@example.com', 'user5post84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'User5Post84'), notification=False)
        r.raise_for_status()
        self.usernames_for_user_list_file.append('user5post84')
        self.expected_report_generator.add_user(
            AnonymizedUser(user_name='user5post84',
                           user_key=json.loads(r.text)['key'],
                           user_display_name='user5post84'))

        # User with only lower-case letter in name; deleted.
        r = self.jira_application.admin_session.user_create('user9post84', 'user9post84@example.com', 'user9post84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'User9Post84'), notification=False)
        r.raise_for_status()
        self.usernames_for_user_list_file.append('user9post84')
        # In Jira version <8.10, deleted users won't be anonymized, because the REST API won't find them.
        # The user-key is None in this case. But in version >= 8.10 the API do find them.
        # TODO Create different data for Jira < 8.10
        self.expected_report_generator.add_user(
            AnonymizedUser(user_name='user9post84',
                           user_key=json.loads(r.text)['key'],
                           user_display_name='user9post84',
                           deleted=True,
                           anonymized_user_display_name=''))

        # A user with a name looking like an anonymized user, but isn't anonymized.
        # Jira doesn't anonymize such user-name. And in versions less than 8.10 the user-key neither.
        # But it anonymizes the user display-name.
        r = self.jira_application.admin_session.user_create('JIRAUSER21111', 'JIRAUSER21111@example.com',
                                                            'JIRAUSER21111',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                'JIRAUSER21111'), notification=False)
        r.raise_for_status()
        self.usernames_for_user_list_file.append('JIRAUSER21111')
        self.expected_report_generator.add_user(
            AnonymizedUser(user_name='JIRAUSER21111',
                           user_key=json.loads(r.text)['key'],
                           user_display_name='JIRAUSER21111',
                           anonymized_user_name='JIRAUSER21111',
                           anonymized_user_key=json.loads(r.text)['key']))

        # Let each user become an issue-creator.
        for user_name in self.usernames_for_user_list_file:
            self.create_issue_and_update_userpicker_customfield_by_user(user_name)

        # Make most users inactive users.
        for user_name in self.usernames_for_user_list_file:
            # Let there be 2 user active.
            if user_name in ['User2Pre84', 'User2Post84']:
                continue
            r = self.jira_application.admin_session.user_deactivate(user_name)
            r.raise_for_status()

        # Get predicted user-data (before some users are going to be deleted).
        #r = self.jira_application.get_predicted_anonymized_userdata(self.usernames_for_user_list_file)
        #r.raise_for_status()
        #self.expected_report_generator.predicted_anonymized_userdata = r.json()
        #self.predicted_anonymized_userdata = r.json()

        self.expected_report_generator.overview = {
            "number_of_users_in_user_list_file": 11,
            "number_of_skipped_users": 2,
            "number_of_anonymized_users": 9,
            "is_background_reindex_triggered": False
        }

        self.expected_report_generator.generate()

        expected_anonymizing_report_json = dataclasses.asdict(self.expected_report_generator)['report']
        log.info("expected_anonymizing_report_json after update:\n{}".format(
            json.dumps(expected_anonymizing_report_json, indent=4)))

        # The following file is for documenting the test.
        with open(self.base_dir_name + '/predicted_anonymized_userdata.json', 'w') as f:
            f.write(json.dumps(r.json(), indent=4))

        # Delete the following users to test validation or anonymization of deleted users.
        # Anonymization of deleted users works since Jira 8.10.
        if self.is_include_users_from_generated_test_resouces:
            r = self.jira_application.admin_session.user_remove('user9pre84')
            r.raise_for_status()
        r = self.jira_application.admin_session.user_remove('User9Post84')
        r.raise_for_status()

        user_list_file_path = self.base_dir_name + '/users.cfg'
        self.write_usernames_to_user_list_file(self.usernames_for_user_list_file, filepath=user_list_file_path)
        self.config_file_path = self.base_dir_name + '/my-test-config.cfg'
        self.create_config_file(filename=self.config_file_path, user_list_file=user_list_file_path)

        #self.assertFalse(True)

        out_dir = self.base_dir_name + '/anonymize'
        out_logfile = out_dir + '/log.out'
        r = self.execute_anonymizer_and_log_output(f'anonymize -c {self.config_file_path} -o {out_dir}', out_logfile)
        self.assertEqual(0, r.returncode)

        with open(pathlib.Path(out_dir).joinpath('anonymizing_report.json'), 'r') as f:
            got_anonymizing_report_json = json.loads(f.read())

        exclude_regex_paths = [r"root\['users'\]\[\d+\]\['time_(start|finish|duration)'\]"]
        ddiff = DeepDiff(expected_anonymizing_report_json, got_anonymizing_report_json,
                         exclude_regex_paths=exclude_regex_paths)
        self.assertFalse(ddiff)

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
            url=self.jira_application.base_url,
            username=user_name,
            password=self.jira_application.get_password_for_jira_user(user_name),
            advanced_mode=True)

        issue_summary = f'User {user_name} created this issue'
        # TODO make the project-ID a variable of BaseTestClass.
        # TODO make the issue-ID a variable of BaseTestClass.
        body = {
            'project': {
                'id': '10000'
            },
            'summary': issue_summary,
            'issuetype': {
                'id': '10002'
            }
        }
        r = jira_user_session.create_issue(fields=body, update_history=True)
        r.raise_for_status()
        issue_key = r.json()['key']
        # customfield_10007: The single user picker custom field 'My-Userpicker'.
        # TODO make the customfiels-ID a variable of BaseTestClass.
        r = jira_user_session.update_issue_field(issue_key, {'customfield_10200': {'name': user_name}})
        r.raise_for_status()
        # The permission scheme allows only project-admins changing the reporter.
        r = self.jira_application.admin_session.update_issue_field(issue_key, {'reporter': {'name': 'admin'}})
        r.raise_for_status()
        jira_user_session.close()


@dataclass
class AnonymizedUser:
    user_name: str = None
    user_key: str = None
    user_display_name: str = None
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
        user_names = [user.user_name for user in self.users]
        log.info(f"user_names {user_names}")
        r = self.jira_application.get_predicted_anonymized_userdata(user_names)
        r.raise_for_status()
        predicted_anonymized_userdata = r.json()
        log.info(f"predicted_anonymized_userdata {predicted_anonymized_userdata}")

        for user in self.users:
            paud_for_user = predicted_anonymized_userdata[user.user_name]

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
                    user.user_key = None
                    user.user_display_name = None
                    user.active = None
                    user.validation_has_errors = False
                    user.filter_is_anonymize_approval = False
                    # This message comes from Jiras REST API.
                    #user.filter_error_message = f"The user named '{user.user_name}' does not exist"
                    user.filter_error_message = self.jira_application.get_error_msg_missing_user(user.user_name)
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

import dataclasses
import json
import logging

from deepdiff import DeepDiff

from base_test_class import BaseTestClass, AnonymizedUser, ExpectedReportGenerator

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdAnonymize(BaseTestClass):
    """
    This test needs a running Jira instance.
    This test can be repeated without restarting Jira.
    """

    def setUp(self):
        super(TestCmdAnonymize, self).setUp()

    def tearDown(self):
        super(TestCmdAnonymize, self).tearDown()

        # for user_name in self.usernames_for_user_list_file:
        #    self.user_activate(user_name)

    def test_01(self):
        """
        Test if duplicate user-names are detected and filtered-out.
        Jira-users must be unique regardless of upper or lowercase letters: The user-names 'user1' and 'User1' are
        the same user. If such equal user-names are in the Anonymizer's usernames-infile, they have to be detected and
        reported to not trigger multiple anonymizations for the same user.

        Setting up these tests is quite specific to these tests, so all set-up stuff is placed here.
        """

        self.out_base_dir_path.mkdir(parents=True)
        self.usernames_for_user_list_file = []
        self.expected_report_generator = ExpectedReportGenerator(self.jira_application)
        self.expected_report_generator.jira_version = self.jira_application.version_numbers

        # This user might exist. In that case ignore the error.
        r = self.jira_application.admin_session.user_create(
            username='new_owner',
            email='new_owner@example.com',
            display_name='New Owner',
            password=self.jira_application.get_password_for_jira_user('new_owner'),
            notification=False)
        # No r.raise_for_status() as that user might be already existing.

        #
        # The following user has been created in Jira >= 8.4.
        #

        # User with upper- and lower-case chars in name.
        user_name = 'user1'
        display_name = 'User 1'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'user2'
        display_name = 'User 2'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'user3'
        display_name = 'User 3'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'User1'
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           filter_error_message='Duplicate in user-name-file',
                           active=None,
                           deleted=None,
                           anonymized_user_name='',
                           anonymized_user_key='',
                           anonymized_user_display_name='',
                           action='skipped'))

        user_name = 'user4'
        display_name = 'User 4'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'USER3'
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           filter_error_message='Duplicate in user-name-file',
                           active=None,
                           deleted=None,
                           anonymized_user_name='',
                           anonymized_user_key='',
                           anonymized_user_display_name='',
                           action='skipped'))

        # Let each user become an issue-creator.
        for user_name in self.usernames_for_user_list_file:
            r = self.jira_application.create_issue_and_update_userpicker_customfield_by_user(user_name)

        # Make users inactive users.
        for user_name in self.usernames_for_user_list_file:
            r = self.jira_application.admin_session.user_deactivate(user_name)
            r.raise_for_status()

        self.expected_report_generator.overview = {
            'number_of_users_in_user_list_file': 6,
            'number_of_skipped_users': 2,
            'number_of_anonymized_users': 4,
            'is_background_reindex_triggered': False
        }
        self.expected_report_generator.generate()

        expected_anonymizing_report_json = dataclasses.asdict(self.expected_report_generator)['report']
        log.info("expected_anonymizing_report_json after update:\n"
                 f"{json.dumps(expected_anonymizing_report_json, indent=4, ensure_ascii=False)}")

        # The following file is for documenting the tests.
        with open(self.out_base_dir_path.joinpath('predicted_anonymized_userdata.json'), 'w') as f:
            f.write(json.dumps(r.json(), indent=4))

        user_list_file_path = self.out_base_dir_path.joinpath('users.cfg')
        self.write_usernames_to_user_list_file(self.usernames_for_user_list_file, filepath=user_list_file_path)
        self.config_file_path = self.out_base_dir_path.joinpath('my-tests-config.cfg')
        self.write_config_file(filename=self.config_file_path, user_list_file=user_list_file_path)

        out_dir = self.out_base_dir_path.joinpath('anonymize')
        out_logfile = out_dir.joinpath('log.out')
        r = self.execute_anonymizer(f'anonymize -c {self.config_file_path} -o {out_dir}', is_log_output=True,
                                    out_filepath=out_logfile)
        self.assertEqual(0, r.returncode)

        with open(out_dir.joinpath('report.json'), 'r') as f:
            got_anonymizing_report_json = json.loads(f.read())

        exclude_regex_paths = [r"root\['users'\]\[\d+\]\['anonymization_(start_time|finish_time|duration)'\]"]
        ddiff = DeepDiff(expected_anonymizing_report_json, got_anonymizing_report_json,
                         exclude_regex_paths=exclude_regex_paths)
        self.assertFalse(ddiff,
                         f"\nexpected_anonymizing_report_json: {json.dumps(expected_anonymizing_report_json, indent=2)}"
                         f"\ngot_anonymizing_report_json: {json.dumps(got_anonymizing_report_json, indent=2)}")

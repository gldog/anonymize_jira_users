import dataclasses
import json
import logging
from multiprocessing import Process

from deepdiff import DeepDiff

from base_test_class import BaseTestClass, ExpectedReportGenerator, AnonymizedUser

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdAnonymize(BaseTestClass):

    def setUp(self):
        super(TestCmdAnonymize, self).setUp()

    def tearDown(self):
        super(TestCmdAnonymize, self).tearDown()

    def test_01(self):
        """
        Setting up these tests is quite specific to these tests, so all set-up stuff is placed here.
        """
        self.is_include_users_from_generated_test_resources = False

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
        # Add users to the list of users to be processed (validated or anonymized).
        # The following user has been created in Jira >= 8.4.
        #

        user_name = 'User1Post84'
        display_name = 'User 1 Post 84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'user5post84'
        display_name = 'user5post84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        # Let each user become an issue-creator.
        for user in self.expected_report_generator.users:
            r = self.jira_application.create_issue_and_update_userpicker_customfield_by_user(user.name)

        # Make users inactive users.
        for user in self.expected_report_generator.users:
            r = self.jira_application.admin_session.user_deactivate(user.name)
            r.raise_for_status()

        self.expected_report_generator.overview = {
            'number_of_users_in_user_list_file': 2,
            'number_of_skipped_users': 0,
            'number_of_anonymized_users': 2,
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

        username = 'the-renamed'
        display_name = 'The Renamed'
        self.jira_application.create_user_if_absent(username=username, email='dummy-user@example.com',
                                                    display_name=display_name, password='1')

        # rename_user(self, username, display_name, num_renames=None)

        # t = Thread(target=self.jira_application.rename_user, args=(username, display_name))
        # t.start()

        proc = Process(target=self.jira_application.rename_user, args=(username, display_name))
        proc.start()

        r = self.execute_anonymizer(f'anonymize -c {self.config_file_path} -o {out_dir}', is_log_output=True,
                                    out_filepath=out_logfile)

        proc.terminate()

        self.assertEqual(0, r.returncode)

        with open(out_dir.joinpath('report.json'), 'r') as f:
            got_anonymizing_report_json = json.loads(f.read())

        exclude_regex_paths = [r"root\['users'\]\[\d+\]\['anonymization_(start_time|finish_time|duration)'\]"]
        ddiff = DeepDiff(expected_anonymizing_report_json, got_anonymizing_report_json,
                         exclude_regex_paths=exclude_regex_paths)
        self.assertFalse(ddiff,
                         f"\nexpected_anonymizing_report_json: {json.dumps(expected_anonymizing_report_json, indent=2)}"
                         f"\ngot_anonymizing_report_json: {json.dumps(got_anonymizing_report_json, indent=2)}")

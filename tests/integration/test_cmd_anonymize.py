import dataclasses
import json
import logging

from deepdiff import DeepDiff

from base_test_class import BaseTestClass, ExpectedReportGenerator, AnonymizedUser

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdAnonymize(BaseTestClass):
    """
    This test(s) needs a running Jira instance.
    his test CAN NOT be repeated. Jira has to be restarted.
    """

    def setUp(self):
        super(TestCmdAnonymize, self).setUp()

    def tearDown(self):
        super(TestCmdAnonymize, self).tearDown()

    def test_01(self):
        """Setting up these tests is quite specific to these tests, so all set-up stuff is placed here. """

        self.is_include_users_from_generated_test_resources = True
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
        #
        if self.is_include_users_from_generated_test_resources:
            #
            # The following user has been created in Jira < 8.4.
            #

            # User with upper- and lower-case chars in name.
            user_name = 'User1Pre84'
            display_name = 'User 1 Pre 84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name))

            # A user that will be kept an active user.
            user_name = 'User2Pre84'
            display_name = 'User 2 Pre 84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name,
                               active=True,
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
                AnonymizedUser(name=user_name,
                               key='user3pre84',
                               display_name=display_name))

            # User with only lower-case letter in name.
            user_name = 'user5pre84'
            display_name = 'user5pre84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name))

            # User with only lower-case letter in name, deleted.
            # The user-name and -display-name are as the user-key for deleted users, and this is
            # also the case for anonymized deleted users.
            # TODO Create different data for Jira < 8.10
            user_name = 'user9pre84'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                # The user-name and -display-name are the ones after deleting this user.
                AnonymizedUser(name='user9pre84',
                               key='user9pre84',
                               display_name='user9pre84',
                               deleted=True,
                               anonymized_user_name='jirauser10111',
                               anonymized_user_key='JIRAUSER10111',
                               anonymized_user_display_name='jirauser10111'))

            # A user with a name (and key) looking like an anonymized user, but isn't anonymized.
            # Jira doesn't anonymize such user-name. And in versions less than 8.10 the user-key neither.
            # But it anonymizes the user display-name.
            # Additional to the test an evaluation is done:
            # Normally, the anonymized user-name is in lower case, and the anonymized user-key is in
            # upper case. The current user has an upper case user-name, and a lower case user-key.
            # Event the cases are inverted, Jira doesn't anonymize the user-name and -key.
            user_name = 'JIRAUSER11111'
            display_name = 'JIRAUSER11111'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name,
                               anonymized_user_name=user_name,
                               anonymized_user_key=user_name.lower()))

            # User with umlaut.
            user_name = 'ä_ö_ü_ß'
            display_name = 'Ä_Ö_Ü_ß'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name))

            # User with spaces.
            user_name = 'Username With Space'
            display_name = 'Username With Space'
            self.usernames_for_user_list_file.append(user_name)
            self.expected_report_generator.add_user(
                AnonymizedUser(name=user_name,
                               key=user_name.lower(),
                               display_name=display_name))
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
                           active=True,
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
        user_name = 'User9Post84'
        display_name = 'User 9 Post 84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        # In Jira version <8.10, deleted users won't be anonymized, because the REST API won't find them.
        # The user-key is None in this case. But in version >= 8.10 the API do find them.
        # TODO Create different data for Jira < 8.10
        user_key = json.loads(r.text)['key']
        self.expected_report_generator.add_user(
            # The user-name and -display-name are the ones after deleting this user.
            AnonymizedUser(name='user9post84',
                           key=user_key,
                           display_name='user9post84',
                           deleted=True,
                           anonymized_user_name=user_key.lower(),
                           anonymized_user_key=user_key,
                           anonymized_user_display_name=user_key.lower()))

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
                           anonymized_user_name='JIRAUSER21111',
                           anonymized_user_key=json.loads(r.text)['key']))

        # User with zero as name. Must not be interpreted as False.
        user_name = '0'
        display_name = '0'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'Username With Space Post84'
        display_name = 'Username With Space Post84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name,
                                                        email='with_space_post84@example.com')
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        user_name = 'ä_ö_ü_ß_post84'
        display_name = 'Ä_Ö_Ü_ß_Post84'
        r = self.jira_application.create_user_if_absent(user_name, display_name=display_name,
                                                        email='ä_ö_ü_ß_post84@example.com')
        r.raise_for_status()
        self.usernames_for_user_list_file.append(user_name)
        self.expected_report_generator.add_user(
            AnonymizedUser(name=user_name,
                           key=json.loads(r.text)['key'],
                           display_name=display_name))

        # user_name = 'パスワード'
        # display_name = '現在 のログイ ン失敗'
        # r = self.jira_application.create_user_if_absent(user_name, display_name=display_name)
        # r.raise_for_status()
        # self.usernames_for_user_list_file.append(user_name)
        # self.expected_report_generator.add_user(
        #     AnonymizedUser(name=user_name,
        #                    key=json.loads(r.text)['key'],
        #                    display_name=display_name))

        # Let each user become an issue-creator.
        for user in self.expected_report_generator.users:
            r = self.jira_application.create_issue_and_update_userpicker_customfield_by_user(user.name)
            # Un-assign issue in case of users to be deleted. A user can only be deleted if not an assignee.
            if user.name.lower() in ['user9pre84', 'user9post84']:
                issue_key = r.json()['key']
                self.jira_application.admin_session.assign_issue(issue=issue_key, account_id=None)

        # Make most users inactive users.
        for user in self.expected_report_generator.users:
            # Let there be 2 user active.
            if user.name.lower() in ['user2pre84', 'user2post84']:
                user.action = 'skipped'
                continue
            r = self.jira_application.admin_session.user_deactivate(user.name)
            r.raise_for_status()

        number_of_users_in_user_list_file = 16 if self.is_include_users_from_generated_test_resources else 8
        is_jiraversion_lt810 = self.jira_application.is_jiraversion_lt810()
        if self.is_include_users_from_generated_test_resources:
            # In Jira-version less than 8.10, deleted users won't be anonymized. The REST-API can't find them.
            if is_jiraversion_lt810:
                number_of_skipped_users = 4
            else:
                number_of_skipped_users = 2
        else:
            if is_jiraversion_lt810:
                number_of_skipped_users = 2
            else:
                number_of_skipped_users = 1

        self.expected_report_generator.overview = {
            'number_of_users_in_user_list_file': number_of_users_in_user_list_file,
            'number_of_skipped_users': number_of_skipped_users,
            'number_of_anonymized_users': number_of_users_in_user_list_file - number_of_skipped_users,
            'is_background_reindex_triggered': False
        }
        self.expected_report_generator.generate()

        expected_anonymizing_report_json = dataclasses.asdict(self.expected_report_generator)['report']
        # log.info("expected_anonymizing_report_json after update:\n"
        #         f"{json.dumps(expected_anonymizing_report_json, indent=4, ensure_ascii=False)}")

        # The following file is for documenting the tests.
        with open(self.out_base_dir_path.joinpath('predicted_anonymized_userdata.json'), 'w') as f:
            f.write(json.dumps(r.json(), indent=4))

        # Delete the following users to tests validation or anonymization of deleted users.
        # Anonymization of deleted users works since Jira 8.10.
        if self.is_include_users_from_generated_test_resources:
            r = self.jira_application.admin_session.user_remove('user9pre84')
            r.raise_for_status()
        r = self.jira_application.admin_session.user_remove('user9post84')
        r.raise_for_status()

        user_list_file_path = self.out_base_dir_path.joinpath('users.cfg')

        self.write_usernames_to_user_list_file(
            # Use lower names to check if the Anonymizer can handle those.
            [user_name.lower() for user_name in self.usernames_for_user_list_file],
            filepath=user_list_file_path)
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

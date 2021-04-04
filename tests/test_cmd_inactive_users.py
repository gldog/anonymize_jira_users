import logging
import pathlib
from typing import List

from base_test_class import BaseTestClass
from jira_user import JiraUser

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdInactiveUsers(BaseTestClass):

    def setUp(self):
        super(TestCmdInactiveUsers, self).setUp()

    def tearDown(self):
        super(TestCmdInactiveUsers, self).tearDown()

        # for user_name in self.usernames_for_user_list_file:
        #    self.user_activate(user_name)

    def test_01(self):

        self.jira_application.admin_session.user_create(
            username='new_owner',
            email='new_owner@example.com',
            display_name='New Owner',
            password=self.jira_application.get_password_for_jira_user('new_owner'),
            notification=False)
        # No r.raise_for_status() here as that user might be already existing.

        users_for_user_list_file = []

        users_to_be_created = [
            JiraUser(name='u01', display_name='U 01',
                     email_address='u01@example.com'),
            JiraUser(name='u02', display_name='U 02',
                     email_address='u02@example.com'),
            JiraUser(name='u03_in_eg_1', display_name='U 03 in exclude_group_1',
                     email_address='u03_in_eg_1@example.com'),
            JiraUser(name='u04_in_eg_1', display_name='U 04 in exclude_group_1',
                     email_address='u04_in_eg_1@example.com'),
            JiraUser(name='u05_in_eg_2', display_name='U 05 in exclude_group_2',
                     email_address='u05_in_eg_2@example.com'),
            JiraUser(name='u06_in_eg_2', display_name='U 06 in exclude_group_2',
                     email_address='u06_in_eg_2@example.com'),
            JiraUser(name='u07_in_eg_1_and_2', display_name='U 07 in exclude_group_1 and _2',
                     email_address='u07_in_eg_1_and_2@example.com')
        ]

        for user in users_to_be_created:
            self.jira_application.admin_session.user_remove(user.name)
            # No r.raise_for_status() here as that user might not exist.
            r = self.jira_application.admin_session.user_create(
                username=user.name,
                email=user.email_address,
                display_name=user.display_name,
                password=self.jira_application.get_password_for_jira_user('u1'), notification=False)
            r.raise_for_status()
            # Need the user-key which is only given in the response of the user_create().
            u = JiraUser.from_json(r.json())
            users_for_user_list_file.append(u)
            # Make users inactive users. Only inactive users are reported.
            r = self.jira_application.admin_session.user_deactivate(user.name)
            r.raise_for_status()

        self.jira_application.admin_session.create_group('exclude_group_1')
        self.jira_application.admin_session.add_user_to_group('u03_in_eg_1', 'exclude_group_1')
        self.jira_application.admin_session.add_user_to_group('u04_in_eg_1', 'exclude_group_1')
        self.jira_application.admin_session.add_user_to_group('u07_in_eg_1_and_2', 'exclude_group_1')
        self.jira_application.admin_session.create_group('exclude_group_2')
        self.jira_application.admin_session.add_user_to_group('u05_in_eg_2', 'exclude_group_2')
        self.jira_application.admin_session.add_user_to_group('u06_in_eg_2', 'exclude_group_2')
        self.jira_application.admin_session.add_user_to_group('u07_in_eg_1_and_2', 'exclude_group_2')

        subtest_path = f'{self.out_base_dir_path}/test_A'
        pathlib.Path(subtest_path).mkdir(parents=True)
        config_file_path = subtest_path + '/my-tests-config.cfg'
        self.write_config_file(
            filename=config_file_path)
        cmd = f'inactive-users -c {config_file_path} -o {subtest_path}'
        r = self.execute_anonymizer_and_log_output(cmd, subtest_path + '/log.out')
        self.assertEqual(0, r.returncode)
        expected_file_content = self.create_expected_filecontent(users_for_user_list_file, [])
        self.compare_expected_content_with_got_file(expected_file_content, subtest_path + '/inactive_users.cfg')

        subtest_path = f'{self.out_base_dir_path}/test_B'
        pathlib.Path(subtest_path).mkdir(parents=True)
        config_file_path = subtest_path + '/my-tests-config.cfg'
        self.write_config_file(
            filename=config_file_path,
            exclude_groups=['exclude_group_1'])
        cmd = f'inactive-users -c {config_file_path} -o {subtest_path}'
        r = self.execute_anonymizer_and_log_output(cmd, subtest_path + '/log.out')
        self.assertEqual(0, r.returncode)
        expected_file_content = self.create_expected_filecontent(users_for_user_list_file, ['in_eg_1'])
        self.compare_expected_content_with_got_file(expected_file_content, subtest_path + '/inactive_users.cfg')

        subtest_path = f'{self.out_base_dir_path}/test_C'
        pathlib.Path(subtest_path).mkdir(parents=True)
        config_file_path = subtest_path + '/my-tests-config.cfg'
        self.write_config_file(
            filename=config_file_path,
            exclude_groups=['exclude_group_1', 'exclude_group_2'])
        cmd = f'inactive-users -c {config_file_path} -o {subtest_path}'
        r = self.execute_anonymizer_and_log_output(cmd, subtest_path + '/log.out')
        self.assertEqual(0, r.returncode)
        expected_file_content = self.create_expected_filecontent(users_for_user_list_file, ['in_eg_'])
        self.compare_expected_content_with_got_file(expected_file_content, subtest_path + '/inactive_users.cfg')

    @staticmethod
    def create_expected_filecontent(users: List[JiraUser], excludes):

        users_lines = []
        num_remaining_users = 0
        for user in users:
            # Test test-users are named according to their exclude-group-membership.
            # E. g. user 'u03_in_eg_1' is in 'exclude_group_1. Users in exclude-groups must not
            # be part of the inactive_users-file.
            if any(map(user.name.__contains__, excludes)):
                continue
            users_lines.append(f'# {user.name}; {user.key}; {user.display_name}; {user.email_address}')
            users_lines.append(user.name)
            users_lines.append('')
            num_remaining_users += 1

        lines = [
            '# File generated at ...',
            '',
            f'# Users: {num_remaining_users}',
            '',
            '# User attributes: User-name; user-key; display-name; email-address',
            ''
        ]

        lines.extend(users_lines)
        return lines

    def compare_expected_content_with_got_file(self, expected_file_content, filepath):

        expected_file_content = expected_file_content[1:]
        log.info("EXPECTED:")
        log.info(expected_file_content)

        with open(filepath, 'r') as f:
            lines = f.read().splitlines(False)[1:]
            log.info("GOT:")
            log.info(lines)
            self.assertListEqual(expected_file_content, lines)
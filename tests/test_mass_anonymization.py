import logging
import pathlib

import urllib3

from base_test_class import BaseTestClass

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TestMassAnonymization(BaseTestClass):
    """Under construction. """

    def setUp(self):
        super(TestMassAnonymization, self).setUp()

    def tearDown(self):
        super(TestMassAnonymization, self).tearDown()

    def test_01(self):

        pathlib.Path(self.out_base_dir_path).mkdir(parents=True)

        usernames_for_user_list_file = []

        num_runs = 1
        for num_run in range(1, num_runs + 1):
            print(f"Test-run {num_run}")

            num_users = 2
            for num_user in range(1, num_users + 1):
                username = f'tu_{num_run:02d}_{num_user:04d}'
                password = '1'
                email = f'{username}@example.com'
                display_name = f'The User {username}'

                self.jira_application.admin_session.user_create(username=username,
                                                                email=email,
                                                                display_name=display_name,
                                                                password=password)

                self.jira_application.create_issue_and_update_userpicker_customfield_by_user(username)
                self.jira_application.user_activate(username, False)
                usernames_for_user_list_file.append(username)

            user_list_file_path = self.out_base_dir_path.joinpath('users.cfg')
            self.write_usernames_to_user_list_file(usernames_for_user_list_file, filepath=user_list_file_path)
            self.config_file_path = self.out_base_dir_path.joinpath('my-tests-config.cfg')
            self.write_config_file(filename=self.config_file_path, user_list_file=user_list_file_path)

            r = self.execute_anonymizer(
                f'anonymize -c {self.config_file_path} -o {self.out_base_dir_path}', is_log_output=True,
                out_filepath=self.out_base_dir_path + '/log.out')
            # decoded_stdout = r.stdout.decode('Latin-1')
            # decoded_stderr = r.stderr.decode('Latin-1')
            # print("r.returncode {}".format(r.returncode))
            # print("r.stderr {}".format(decoded_stderr))
            # print("r.stdout {}".format(decoded_stdout))

            # report_file = pathlib.Path(report_dir).joinpath('anonymizing_report.json')
            # with open(report_file) as f:
            #    report_json = json.load(f)
            #    for user in report_json['users']:
            #        print("Checking user {}".format(user['user_name']))
            #        self.assertTrue(user['anonymized_user_name'])
            #        self.assertTrue(user['anonymized_user_key'])
            #        self.assertTrue(user['anonymized_user_display_name'])

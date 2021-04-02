import logging
import tempfile
import textwrap

import urllib3

from base_test_class import BaseTestClass

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Test01(BaseTestClass):

    def setUp(self):
        super(Test01, self).setUp()

        self.config_file = tempfile.NamedTemporaryFile(mode='w', prefix='config__')
        self.user_list_file = tempfile.NamedTemporaryFile(mode='w', prefix='assessed_inactive_users__')
        self.config_file.write(textwrap.dedent(f"""\
            [DEFAULT]
            jira_base_url = http://localhost:2990/jira
            jira_auth = Basic admin:admin
            user_list_file = {self.user_list_file.name}
            new_owner = new_owner
            # Speed up things a little bit (defaults are 10/3):
            initial_delay = 2
            regular_delay = 2"""))
        self.config_file.flush()

        log.info(
            f"config_file: {self.config_file.name}, assessed_inactive_users_file: {self.user_list_file.name}")

    def tearDown(self):
        super(Test01, self).tearDown()

        r = self.execute_anonymizer(f'{self.action} -c {self.config_file.name} -o {self.out_dir}')
        decoded_stdout = r.stdout.decode('Latin-1')
        decoded_stderr = r.stderr.decode('Latin-1')
        # result contains: result.returncode, result.stderr, result.stdout.
        print("r.returncode {}".format(r.returncode))
        print("r.stderr {}".format(decoded_stderr))
        print("r.stdout {}".format(decoded_stdout))

        self.config_file.close()
        self.user_list_file.close()

    def test_manual_example_1(self):
        # self.set_active_status_of_user('User1Pre84', False)

        user1 = 'User1Pre84'
        user2 = 'User1Post84'

        self.jira_application.user_activate(user1, False)
        # self.create_user('User1Post84', 'User 1 Post 84')
        r = self.jira_application.admin_session.user_create(user2, f'{user2}@example.com', 'User 1 Post 84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                user2), notification=False)
        # self.set_active_status_of_user('User1Post84', False)
        self.jira_application.user_activate(user2, False)

        self.user_list_file.write('\n'.join([user1, user2]))
        self.user_list_file.flush()

        self.action = 'validate'
        self.out_dir = 'manual/ex1'

    def test_manual_example_2(self):
        user1 = 'User2Pre84'

        self.jira_application.user_activate(user1, True)

        self.user_list_file.write('\n'.join([user1, 'deleted-user', 'user-from-ad']))
        self.user_list_file.flush()

        self.action = 'anonymize'
        self.out_dir = 'manual/ex2'

    def test_manual_example_3(self):
        user1 = 'User6Pre84'
        user2 = 'User7Pre84'
        user3 = 'User1Post84'
        user4 = 'User2Post84'

        self.jira_application.user_activate(user1, False)

        self.jira_application.user_activate(user2, True)
        self.jira_application.admin_session.assign_issue('KSP-1', user2)
        self.jira_application.user_activate(user2, False)

        r = self.jira_application.admin_session.user_create(user3, f'{user3}@example.com', 'User 1 Post 84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                user3), notification=False)
        self.jira_application.user_activate(user3, False)

        r = self.jira_application.admin_session.user_create(user4, f'{user4}@example.com', 'User 2 Post 84',
                                                            password=self.jira_application.get_password_for_jira_user(
                                                                user4), notification=False)
        self.jira_application.admin_session.assign_issue('KSP-2', user4)
        self.jira_application.user_activate(user4, False)

        self.user_list_file.write('\n'.join([user1, user2, user3, user4]))
        self.user_list_file.flush()

        self.action = 'anonymize'
        self.out_dir = 'manual/ex3'

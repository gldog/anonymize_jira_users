import logging
import os
import shutil

import urllib3

from base_test_class import BaseTestClass

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Test01(BaseTestClass):

    def setUp(self):
        super(Test01, self).setUp()
        pass

    def tearDown(self):
        super(Test01, self).tearDown()
        pass

    def test_01(self):

        report_base_dir = os.path.splitext(os.path.basename(__file__))[0]
        if os.path.exists(report_base_dir):
            shutil.rmtree(report_base_dir)

        user_name_11 = 'User1Pre84'
        user_name_12 = 'User3Pre84_renamed'
        user_name_13 = 'user5pre84'
        user_name_14 = 'user-abcd1'
        user_name_15 = 'JIRAUSER11111'

        user_name_21 = 'User1Post84'
        user_name_22 = 'JIRAUSER21111'
        user_name_23 = 'user-fbcd1'

        self.create_user(user_name_21, 'User 1 Post 84')
        self.create_user(user_name_22, 'jirauser21111')
        self.create_user(user_name_23, 'user-fbcd1')

        self.edit_issue_set_single_user_picker('KSP-1', 'customfield_10007', user_name_11)
        self.edit_issue_set_single_user_picker('KSP-2', 'customfield_10007', user_name_12)
        self.edit_issue_set_single_user_picker('KSP-3', 'customfield_10007', user_name_13)
        self.edit_issue_set_single_user_picker('KSP-4', 'customfield_10007', user_name_14)
        self.edit_issue_set_single_user_picker('KSP-5', 'customfield_10007', user_name_15)
        self.edit_issue_set_single_user_picker('KSP-6', 'customfield_10007', user_name_21)
        self.edit_issue_set_single_user_picker('KSP-7', 'customfield_10007', user_name_22)
        self.edit_issue_set_single_user_picker('KSP-8', 'customfield_10007', user_name_23)

        usernames_for_user_list_file = [
            user_name_11, user_name_12, user_name_13, user_name_14, user_name_15,
            user_name_21, user_name_22, user_name_23]

        for user_name in usernames_for_user_list_file:
            self.remove_user(user_name)

        write_usernames_to_user_list_file(usernames_for_user_list_file)

        self.create_default_test_config_file()
        r = execute_anonymizer('anonymize -c my-tests-config.cfg -o {}'.format(report_base_dir))
        decoded_stdout = r.stdout.decode()
        decoded_stderr = r.stderr.decode()
        print("r.returncode {}".format(r.returncode))
        print("r.stderr {}".format(decoded_stderr))
        print("r.stdout {}".format(decoded_stdout))

        # report_file = pathlib.Path(report_base_dir).joinpath('anonymizing_report.json')
        # with open(report_file) as f:
        #    report_json = json.load(f)
        # for user in report_json['users']:
        #    print("Checking user {}".format(user['user_name']))
        #    self.assertTrue(user['anonymized_user_name'])
        #    self.assertTrue(user['anonymized_user_key'])
        #    self.assertTrue(user['anonymized_user_display_name'])

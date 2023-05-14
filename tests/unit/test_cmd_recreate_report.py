import json
import logging
import os
import pathlib
import tempfile

from deepdiff import DeepDiff

from base_test_class import BaseTestClass

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestCmdRecreateReport(BaseTestClass):

    def setUp(self):
        super(TestCmdRecreateReport, self).setUp()
        self.current_path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))

    def tearDown(self):
        super(TestCmdRecreateReport, self).tearDown()

    def test_01(self):
        report_details_json_dict = {
            "effective_config": {
                "subparser_name": "anonymize"
            },
            "execution_logger": {},
            "users": [
                {
                    "name": "user1",
                    "key": "JIRAUSER10415",
                    "display_name": "User 1",
                    "email_address": "user1@example.com",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:20:58.430+0200",
                    "anonymization_finish_time": "2021-09-15T21:20:58.523+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10415",
                    "anonymized_user_key": "JIRAUSER10415",
                    "anonymized_user_display_name": "user-6e601",
                    "action": "anonymized",
                    "logs": {}
                },
                {
                    "name": "user2",
                    "key": "JIRAUSER10416",
                    "display_name": "User 2",
                    "email_address": "user2@example.com",
                    "active": False,
                    # Simulate Jira < 8.10: Atlassian introduced the deleted-attribute in Jira 8.10.
                    # "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:01.538+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:01.604+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10416",
                    "anonymized_user_key": "JIRAUSER10416",
                    "anonymized_user_display_name": "user-74bbc",
                    "action": "anonymized",
                    "logs": {}
                },
                {
                    "name": "user3",
                    "key": "JIRAUSER10417",
                    "display_name": "User 3",
                    "email_address": "user3@example.com",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:04.638+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:04.703+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10417",
                    "anonymized_user_key": "JIRAUSER10417",
                    "anonymized_user_display_name": "user-907f3",
                    "action": "anonymized",
                    "logs": {}
                },
                {
                    "name": "User1",
                    "key": None,
                    "display_name": None,
                    "email_address": None,
                    "active": None,
                    "deleted": None,
                    "filter_error_message": "Duplicate in user-name-file",
                    "anonymization_start_time": None,
                    "anonymization_finish_time": None,
                    "anonymization_duration": None,
                    "anonymized_user_name": "",
                    "anonymized_user_key": "",
                    "anonymized_user_display_name": "",
                    "action": "skipped",
                    "logs": {}
                },
                {
                    "name": "user4",
                    "key": "JIRAUSER10418",
                    "display_name": "User 4",
                    "email_address": "user4@example.com",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:07.732+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:07.812+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10418",
                    "anonymized_user_key": "JIRAUSER10418",
                    "anonymized_user_display_name": "user-6d31c",
                    "action": "anonymized",
                    "logs": {}
                }

            ]
        }

        expected_report_json_dict = {
            "overview": {
                "number_of_users_in_user_list_file": 5,
                "number_of_skipped_users": 1,
                "number_of_anonymized_users": 4,
                "is_background_reindex_triggered": False
            },
            "users": [
                {
                    "name": "user1",
                    "key": "JIRAUSER10415",
                    "display_name": "User 1",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:20:58.430+0200",
                    "anonymization_finish_time": "2021-09-15T21:20:58.523+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10415",
                    "anonymized_user_key": "JIRAUSER10415",
                    "anonymized_user_display_name": "user-6e601",
                    "action": "anonymized"
                },
                {
                    "name": "user2",
                    "key": "JIRAUSER10416",
                    "display_name": "User 2",
                    "active": False,
                    # Simulate Jira < 8.10: Atlassian introduced the deleted-attribute in Jira 8.10.
                    "deleted": None,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:01.538+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:01.604+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10416",
                    "anonymized_user_key": "JIRAUSER10416",
                    "anonymized_user_display_name": "user-74bbc",
                    "action": "anonymized"
                },
                {
                    "name": "user3",
                    "key": "JIRAUSER10417",
                    "display_name": "User 3",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:04.638+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:04.703+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10417",
                    "anonymized_user_key": "JIRAUSER10417",
                    "anonymized_user_display_name": "user-907f3",
                    "action": "anonymized"
                },
                {
                    "name": "User1",
                    "key": None,
                    "display_name": None,
                    "active": None,
                    "deleted": None,
                    "filter_error_message": "Duplicate in user-name-file",
                    "anonymization_start_time": None,
                    "anonymization_finish_time": None,
                    "anonymization_duration": None,
                    "anonymized_user_name": "",
                    "anonymized_user_key": "",
                    "anonymized_user_display_name": "",
                    "action": "skipped"
                },
                {
                    "name": "user4",
                    "key": "JIRAUSER10418",
                    "display_name": "User 4",
                    "active": False,
                    "deleted": False,
                    "filter_error_message": "",
                    "anonymization_start_time": "2021-09-15T21:21:07.732+0200",
                    "anonymization_finish_time": "2021-09-15T21:21:07.812+0200",
                    "anonymization_duration": "00:01",
                    "anonymized_user_name": "jirauser10418",
                    "anonymized_user_key": "JIRAUSER10418",
                    "anonymized_user_display_name": "user-6d31c",
                    "action": "anonymized"
                }
            ]
        }

        with tempfile.TemporaryDirectory(prefix='report_parent_path_') as report_parent_path:
            with tempfile.NamedTemporaryFile(mode='w', prefix='report_details_json_') as report_details_json_file:
                report_details_json_file.write(json.dumps(report_details_json_dict))
                report_details_json_file.flush()
                report_path = pathlib.Path(report_parent_path, 'report')
                log.info(f"report_details_json_file: {report_details_json_file.name}"
                         f", report_parent_path: {report_parent_path}"
                         f", report_path: {report_path}")
                cmd = f'recreate-report -i {report_details_json_file.name} -o {report_path}'
                r = self.execute_anonymizer(cmd, is_log_output=True)
                self.assertEqual(0, r.returncode)
                with open(pathlib.Path(report_path, 'report.json'), 'r') as report_json_file:
                    report_json_dict = json.load(report_json_file)
                    ddiff = DeepDiff(expected_report_json_dict, report_json_dict)
                    self.assertFalse(ddiff,
                                     f"\nexpected_report_json: {json.dumps(expected_report_json_dict, indent=2)}\n"
                                     f"report_json_dict: {json.dumps(report_json_dict, indent=2)}")

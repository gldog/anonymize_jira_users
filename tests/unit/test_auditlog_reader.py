import json
import logging
import os
import pathlib
import re
import unittest
from dataclasses import dataclass
from os import listdir
from unittest.mock import Mock

from auditlog_reader import AuditlogReader
from jira_user import JiraUser

log = logging.getLogger()
logging.basicConfig(level=logging.DEBUG)


class TestAuditlogReader(unittest.TestCase):
    """ Test the auditlog_reader.py.

    Test test-function's naming is (mostly):
    <jira-version>_with_<system-default-language>_<user-settings-language>_with_<api-type>_<test-description>.

    In hindsight the user-settings-language seems not of interest.

    The tests are ordered:
    - specific tests with a single JSON-resource
    - batch-tests with a folder of JSON-resources

    They are devided in:
    - API: deprecated record-API and new event-API

    """

    log = logging.getLogger()
    logging.basicConfig(level=logging.DEBUG)

    versions_less_than_8_10 = ['8.7.0', '8.8.0', '8.9.0']

    @staticmethod
    def is_version_less_than_8_10(version):
        """Check if the version given as string in the format <major>.<minor>.<patch> is less than 8.10.
        See also jira.is_jira_version_less_then().
        """
        version_numbers = re.split('[.]', version)
        return int(version_numbers[0]) < 8 or (int(version_numbers[0]) == 8 and int(version_numbers[1]) < 10)

    def setUp(self):
        super(TestAuditlogReader, self).setUp()

        mock = Mock()
        self.reader = AuditlogReader(config=mock, log=log, jira=mock, execution_logger=mock)
        self.current_path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))

    def tearDown(self):
        super(TestAuditlogReader, self).tearDown()

    def test_8_7_0_with_deDE_deDE_with_auditing_record_api_with_additional_dummy_entries_for_User1Post84(self):
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.7.0_deDE_deDE_api_2_auditing_record_user1Pre84_with_additional_dummy_entries.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name='User1Pre84', key='JIRAUSER10103')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('user-57690', user.anonymized_user_display_name, file_path)

    def test_8_7_0_with_enUS_enUS_with_auditing_record_api_for_user_q_1(self):
        # Q means Quote, as a file containing a ' can't be checked-out in Git in Windows.
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 "8.7.0_enUS_enUS_api_2_auditing_record_userQ1.json")
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name="user'1", key='JIRAUSER10400')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10400', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10400', user.anonymized_user_key, file_path)
        self.assertEqual('user-14aa9', user.anonymized_user_display_name, file_path)

    def test_8_7_0_with_enUS_enUS_with_auditing_record_api_for_user_dq_2(self):
        # dq means double quote because the double quote is an invalid character for function names.
        # DQ means Double Quote, as the " can't be checked-out in Git in Windows.
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.7.0_enUS_enUS_api_2_auditing_record_userDQ2.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name='user"2', key='JIRAUSER10401')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10401', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10401', user.anonymized_user_key, file_path)
        self.assertEqual('user-04cab', user.anonymized_user_display_name, file_path)

    def test_8_7_0_with_deDE_deDE_with_auditing_record_api_for_already_anonymized_jirauser10103(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has fewer entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.7.0_deDE_deDE_api_2_auditing_record_already_anonymized_jirauser10103.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name='jirauser10103', key='JIRAUSER10103', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_7_0_with_xxXX_deDE_with_auditing_record_api_for_jirauser11111(self):
        """xxXX: Don't know what lang was setting at time of anonymization.
        The user looks like an anonymized user regarding the user-name and user-key, but it
        isn't."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.7.0_xxXX_deDE_api_2_auditing_record_JIRAUSER11111.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name='JIRAUSER11111', key='jirauser11111')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('JIRAUSER11111', user.anonymized_user_name, file_path)
        self.assertEqual('jirauser11111', user.anonymized_user_key, file_path)
        self.assertEqual('user-438f1', user.anonymized_user_display_name, file_path)

    def test_8_7_0_with_enUS_enUS_with_auditing_record_api_for_user3pre84_renamed(self):
        """The user was initially created with user-name user3pre84 in Jira version <8.4,
        and then renamed to user3pre84_renamed. The user-key is still user3pre84. """
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.7.0_enUS_enUS_api_2_auditing_record_user3pre84_renamed.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

        user = JiraUser(name='User3Pre84_renamed', key='user3pre84', display_name='User 3 Pre 84 (renamed)')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                        auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10105', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10105', user.anonymized_user_key, file_path)
        self.assertEqual('user-e175a', user.anonymized_user_display_name, file_path)

    def test_8_10_0_with_deDE_enUS_with_auditing_events_api_for_JIRAUSER11111(self):
        """The name and key looks like an anonymized user, but it isn't. """
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.10.0_deDE_enUS_auditing_1.0_events_JIRAUSER11111.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='JIRAUSER11111', key='jirauser11111', display_name='JIRAUSER11111')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('JIRAUSER11111', user.anonymized_user_name, file_path)
        self.assertEqual('jirauser11111', user.anonymized_user_key, file_path)
        self.assertEqual('user-438f1', user.anonymized_user_display_name, file_path)

    def test_8_10_0_with_enUS_enUS_with_auditing_events_api_for_already_anonymized_jirauser10114(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.10.0_enUS_enUS_auditing_1.0_events_already_anonymized_user_jirauser10114.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10114', key='JIRAUSER10114', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10114', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10114', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_10_0_with_deDE_deDE_with_auditing_events_api_for_already_anonymized_jirauser10103(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.10.0_deDE_deDE_auditing_1.0_events_already_anonymized_user_jirauser10103.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10103', key='JIRAUSER10103', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_11_0_with_enUS_enUS_with_auditing_events_api_for_already_anonymized_jirauser10114(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.11.0_enUS_enUS_auditing_1.0_events_already_anonymized_user_jirauser10114.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10114', key='JIRAUSER10114', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10114', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10114', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_11_0_with_deDE_deDE_with_auditing_events_api_for_already_anonymized_jirauser10103(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.11.0_deDE_deDE_auditing_1.0_events_already_anonymized_user_jirauser10103.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10103', key='JIRAUSER10103', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_13_0_with_deDE_deDE_with_auditing_events_api_with_additional_dummy_entries_for_User1Pre84(self):
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.13.0_deDE_deDE_auditing_1.0_events_User1Pre84_with_additional_dummy_entries.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='User1Pre84', key='user1pre84')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('user-57690', user.anonymized_user_display_name, file_path)

    def test_8_14_0_with_enUS_enUS_with_auditing_events_api_for_already_anonymized_jirauser10114(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.14.0_enUS_enUS_auditing_1.0_events_already_anonymized_user_jirauser10114.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10114', key='JIRAUSER10114', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10114', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10114', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_8_14_0_with_deDE_deDE_with_auditing_events_api_for_already_anonymized_jirauser10103(self):
        """The user is already anonymized. Jira allows anonymizing already anonymized user, but
        doesn't do anything. The anonymized user keeps as is.
        The audit log has only 2 entries in this case."""
        file_path = pathlib.Path(self.current_path, 'resources',
                                 'test_auditlog_reader',
                                 'other',
                                 '8.14.0_deDE_deDE_auditing_1.0_events_already_anonymized_user_jirauser10103.json')
        with open(file_path) as f:
            jsn = json.load(f)

        auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

        user = JiraUser(name='jirauser10103', key='JIRAUSER10103', display_name='not_given_in_audit_log')
        user.logs['rest_auditing'] = {'pages': {}}
        self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                       auditlog_iterator=auditlog_iterator)
        self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
        self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
        self.assertEqual('not_given_in_audit_log', user.anonymized_user_display_name, file_path)

    def test_with_deDE_xx_with_auditing_record_api_for_User1Post84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_deDE_for_User1Post84',
                            'api_2_auditing_record')

        # is_version_less_than_8_10

        # About str(path):
        # Until here, path is not of type String. The following code...
        #   f.split('_')[0]
        # ... would result in the warning:
        #   Expected type 'Optional[bytes]', got 'str' instead
        # That works. But the str(path) avoids that warning.
        file_paths = [f for f in listdir(str(path)) if TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

            user = JiraUser(name='User1Post84', key='JIRAUSER10401')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                            auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10401', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10401', user.anonymized_user_key, file_path)
            self.assertEqual('user-04cab', user.anonymized_user_display_name, file_path)

    def test_with_deDE_xx_with_auditing_events_api_for_User1Post84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_deDE_for_User1Post84',
                            'auditing_1.0_events')
        # Exclude some test-files. The function under test is for Jira-versions starting at 8.10.
        file_paths = [f for f in listdir(str(path)) if
                      not TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

            user = JiraUser(name='User1Post84', key='JIRAUSER10401')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                           auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10401', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10401', user.anonymized_user_key, file_path)
            self.assertEqual('user-04cab', user.anonymized_user_display_name, file_path)

    def test_with_deDE_xx_with_auditing_record_api_for_User1Pre84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_deDE_for_User1Pre84',
                            'api_2_auditing_record')
        # Exclude some test-files. The function under test is for Jira-versions starting at 8.10.
        file_paths = [f for f in listdir(str(path)) if TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

            user = JiraUser(name='User1Pre84', key='user1pre84', display_name='User 1 Pre 84')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                            auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
            self.assertEqual('user-57690', user.anonymized_user_display_name, file_path)

    def test_with_deDE_xx_with_auditing_events_api_for_User1Pre84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_deDE_for_User1Pre84',
                            'auditing_1.0_events')
        # Exclude some test-files. The function under test is for Jira-versions starting at 8.10.
        file_paths = [f for f in listdir(str(path)) if
                      not TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

            user = JiraUser(name='User1Pre84', key='user1pre84', display_name='User 1 Pre 84')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                           auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
            self.assertEqual('user-57690', user.anonymized_user_display_name, file_path)

    def test_with_enUS_xx_with_auditing_record_api_for_User1Post84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_enUS_for_User1Post84',
                            'api_2_auditing_record')
        file_paths = [f for f in listdir(str(path)) if TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

            user = JiraUser(name='User1Post84', key='JIRAUSER10401')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                            auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10401', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10401', user.anonymized_user_key, file_path)
            self.assertEqual('user-04cab', user.anonymized_user_display_name, file_path)

    def test_with_enUS_xx_with_auditing_events_api_for_User1Post84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_enUS_for_User1Post84',
                            'auditing_1.0_events')
        file_paths = [f for f in listdir(str(path)) if
                      not TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['entities'])

            user = JiraUser(name='User1Post84', key='JIRAUSER10401')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_events_for_user(user=user,
                                                                           auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10401', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10401', user.anonymized_user_key, file_path)
            self.assertEqual('user-04cab', user.anonymized_user_display_name, file_path)

    def test_with_enUS_xx_with_auditing_record_api_for_User1Pre84(self):
        path = pathlib.Path(self.current_path, 'resources',
                            'test_auditlog_reader',
                            'anon_done_with_enUS_for_User1Pre84',
                            'api_2_auditing_record')
        file_paths = [f for f in listdir(str(path)) if TestAuditlogReader.is_version_less_than_8_10(f.split('_')[0])]
        for file_path in sorted(file_paths):
            file_path = path.joinpath(file_path)
            # log.info(f"file_path: {file_path}")
            with open(file_path) as f:
                jsn = json.load(f)

            auditlog_iterator = TestAuditlogReader.AuditLogIteratorMock(jsn['records'])

            user = JiraUser(name='User1Pre84', key='JIRAUSER10103')
            user.logs['rest_auditing'] = {'pages': {}}
            self.reader.get_anonymized_userdata_from_audit_records_for_user(user=user,
                                                                            auditlog_iterator=auditlog_iterator)
            self.assertEqual('jirauser10103', user.anonymized_user_name, file_path)
            self.assertEqual('JIRAUSER10103', user.anonymized_user_key, file_path)
            self.assertEqual('user-57690', user.anonymized_user_display_name, file_path)

    #
    # Helpers
    #

    @dataclass
    class AuditLogIteratorMock:
        entry_list: dict

        def entries(self):
            return self.entry_list

        def get_current_page(self):
            return {}

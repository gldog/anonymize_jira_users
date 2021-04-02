import json
import locale
import logging
import sys
import tempfile
import textwrap

from base_test_class import BaseTestClass

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class Test01(BaseTestClass):
    """
    The "effective configuration" of the Anonymizer results from a merge of
        - the built-in default configuration with
        - the configuration from a config-file, and with
        - the configuration from command line arguments.

    To read the effective configuration, the Anonymizer is called with parameter --info, which prints the
    effective config to the command line and then exits. The output is:

    Effective config:
    {
        ...
    }

    The tests-groups:

    test_1x: Command 'inactive-users'. Here, only arguments specific to this command are tested.
    test_2x: Command 'anoynmize'. Includes tests of arguments of command 'validate', as 'validate' is
        a sub-set of 'anonymize'.
    """

    def setUp(self):
        # super(Test01, self).setUp()
        pass

    def tearDown(self):
        # super(Test01, self).tearDown()
        pass

    def test_11_command_inactiveusers_with_defaults_only(self):
        expected_config = {
            'subparser_name': 'inactive-users',
            'jira_base_url': '',
            'jira_auth': '<sanitized>',
            'exclude_groups': [],
            'user_list_file': '',
            'encoding': None,
            'report_out_dir': '.',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': False,
            'is_dry_run': False,
            'new_owner': '',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': False,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        r = self.execute_anonymizer('inactive-users --info')
        std_out = r.stdout.decode('utf-8')
        self.assertEqual(0, r.returncode, r)

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        # maxDiff: Required by assertEqual()
        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_12_command_inactiveusers_with_config_file(self):
        expected_config = {
            'subparser_name': 'inactive-users',
            'jira_base_url': '_jira_base_url_',
            'jira_auth': '<sanitized>',
            'exclude_groups': ['groupA1', 'groupA2', 'groupA3 with spaces'],
            'user_list_file': '',
            'encoding': None,
            'report_out_dir': '.',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': False,
            'is_dry_run': False,
            'new_owner': '',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': False,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        config_file = tempfile.NamedTemporaryFile(mode='w', prefix='tests-config')
        config_file.write(textwrap.dedent("""\
            [DEFAULT]
            jira_base_url = _jira_base_url_
            jira_auth = _jira_auth_
            exclude_groups = groupA1
              groupA2
              groupA3 with spaces
            """))
        config_file.flush()

        expected_config['config_file'] = config_file.name

        r = self.execute_anonymizer('inactive-users -c {} --info'.format(config_file.name))
        std_out = r.stdout.decode('utf-8')
        # decoded_stderr = r.stderr.decode('utf-8')
        # print("r.returncode {}".format(r.returncode))
        # print("r.stderr {}".format(decoded_stderr))
        # print("r.stdout {}".format(std_out))

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_13_command_inactiveusers_with_cmdline_arguments(self):
        expected_config = {
            'subparser_name': 'inactive-users',
            'jira_base_url': '',
            'jira_auth': '<sanitized>',
            'exclude_groups': ['groupB1', 'groupB2', 'groupB3 with spaces'],
            'user_list_file': '',
            'encoding': None,
            'report_out_dir': '.',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': False,
            'is_dry_run': False,
            'new_owner': '',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': False,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        cmdline_params = [
            '-G groupB1 groupB2 "groupB3 with spaces"'
        ]

        r = self.execute_anonymizer('inactive-users {} --info'.format(' '.join(cmdline_params)))
        std_out = r.stdout.decode('utf-8')

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_14_command_inactiveusers_with_config_file_and_cmdline_arguments(self):
        expected_config = {
            'subparser_name': 'inactive-users',
            'jira_base_url': '_jira_base_url_',
            'jira_auth': '<sanitized>',
            'exclude_groups': ['groupB1', 'groupB2', 'groupB3 with spaces'],
            'user_list_file': '',
            'encoding': None,
            'report_out_dir': '.',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': False,
            'is_dry_run': False,
            'new_owner': '',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': False,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        config_file = tempfile.NamedTemporaryFile(mode='w', prefix='tests-config')
        config_file.write(textwrap.dedent("""\
            [DEFAULT]
            jira_base_url = _jira_base_url_
            jira_auth = _jira_auth_
            exclude_groups = groupA1
              groupA2
              groupA3 with spaces
            """))
        config_file.flush()

        expected_config['config_file'] = config_file.name

        cmdline_params = [
            '-G groupB1 groupB2 "groupB3 with spaces"'
        ]

        r = self.execute_anonymizer('inactive-users -c {} {} --info'.format(config_file.name, ' '.join(cmdline_params)))
        std_out = r.stdout.decode('utf-8')

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(
            json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_21_command_ananlyize_with_defaults_only(self):
        expected_config = {
            'subparser_name': 'anonymize',
            'jira_base_url': '',
            'jira_auth': '<sanitized>',
            'exclude_groups': [],
            'user_list_file': '',
            'encoding': None,
            'report_out_dir': '.',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': False,
            'is_dry_run': False,
            'new_owner': '',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': False,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        r = self.execute_anonymizer('anonymize --info')
        std_out = r.stdout.decode('utf-8')

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = \
            json.dumps(json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        # maxDiff: Required by assertEqual()
        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_22_command_analyze_with_config_file(self):
        expected_config = {
            'subparser_name': 'anonymize',
            'jira_base_url': '_jira_base_url_',
            'jira_auth': '<sanitized>',
            'exclude_groups': [],
            'user_list_file': '_user_list_file_',
            'encoding': '_encoding_',
            'report_out_dir': '_report_out_dir_',
            'loglevel': 'INFO',
            'is_expand_validation_with_affected_entities': True,
            'is_dry_run': True,
            'new_owner': '_new_owner_',
            'initial_delay': 2,
            'regular_delay': 2,
            'timeout': 1000,
            'is_trigger_background_reindex': True,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        config_file = tempfile.NamedTemporaryFile(mode='w', prefix='tests-config')
        config_file.write(textwrap.dedent("""\
            [DEFAULT]
            loglevel = INFO
            jira_base_url = _jira_base_url_
            jira_auth = _jira_auth_
            user_list_file = _user_list_file_
            encoding = _encoding_
            report_out_dir = _report_out_dir_
            is_expand_validation_with_affected_entities = true
            is_dry_run = true
            new_owner = _new_owner_
            initial_delay = 2
            regular_delay = 2
            timeout = 1000
            is_trigger_background_reindex = true
            """))
        config_file.flush()

        expected_config['config_file'] = config_file.name

        r = self.execute_anonymizer('anonymize -c {} --info'.format(config_file.name))
        std_out = r.stdout.decode('utf-8')
        print("r.returncode {}".format(r.returncode))
        print("r.stderr {}".format(r.stderr.decode('utf-8')))
        print("r.stdout {}".format(std_out))

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(
            json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_23_command_anonymize_with_cmdline_arguments(self):
        expected_config = {
            'subparser_name': 'anonymize',
            'jira_base_url': 'JIRA_BASE_URL',
            'jira_auth': '<sanitized>',
            'exclude_groups': [],
            'user_list_file': 'USER_LIST_FILE',
            'encoding': 'ENCODING',
            'report_out_dir': 'REPORT_OUT_DIR',
            'loglevel': 'ERROR',
            'is_expand_validation_with_affected_entities': True,
            'is_dry_run': True,
            'new_owner': 'NEW_OWNER',
            'initial_delay': 10,
            'regular_delay': 3,
            'timeout': 0,
            'is_trigger_background_reindex': True,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        cmdline_params = [
            '-l ERROR',
            '-b JIRA_BASE_URL',
            '-a ADMIN_USER_AUTH',
            '-o REPORT_OUT_DIR',
            '-i USER_LIST_FILE',
            '--encoding ENCODING',
            '--expand-validation-with-affected-entities',
            '-D',
            '-n NEW_OWNER',
            '-x'
        ]

        r = self.execute_anonymizer('anonymize {} --info'.format(' '.join(cmdline_params)))
        std_out = r.stdout.decode('utf-8')

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(
            json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

    def test_24_command_anonymize_with_config_file_and_cmdline_arguments(self):
        expected_config = {
            'subparser_name': 'anonymize',
            'jira_base_url': 'JIRA_BASE_URL',
            'jira_auth': '<sanitized>',
            'exclude_groups': [],
            'user_list_file': 'USER_LIST_FILE',
            'encoding': 'ENCODING',
            'report_out_dir': 'REPORT_OUT_DIR',
            'loglevel': 'ERROR',
            'is_expand_validation_with_affected_entities': True,
            'is_dry_run': True,
            'new_owner': 'NEW_OWNER',
            'initial_delay': 2,
            'regular_delay': 2,
            'timeout': 1000,
            'is_trigger_background_reindex': True,
            #
            'info': True,
            'locale_getpreferredencoding': str(locale.getpreferredencoding()),
            'sys_getfilesystemencoding': str(sys.getfilesystemencoding()),
            'report_details_filename': 'anonymizing_report_details.json',
            'report_json_filename': 'anonymizing_report.json',
            'report_text_filename': 'anonymizing_report.csv',
        }

        config_file = tempfile.NamedTemporaryFile(mode='w', prefix='tests-config')
        # print("config_file {}".format(config_file.name))
        config_file.write(textwrap.dedent("""\
            [DEFAULT]
            loglevel = _loglevel_
            jira_base_url = _jira_base_url_
            jira_auth = _jira_auth_
            user_list_file = _user_list_file_
            encoding = _encoding_
            report_out_dir = _report_out_dir_
            is_expand_validation_with_affected_entities = false
            is_dry_run = false
            new_owner = _new_owner_
            initial_delay = 2
            regular_delay = 2
            timeout = 1000
            is_trigger_background_reindex = false
            """))
        config_file.flush()

        expected_config['config_file'] = config_file.name

        cmdline_params = [
            '-l ERROR',
            '-b JIRA_BASE_URL',
            '-a ADMIN_USER_AUTH',
            '-o REPORT_OUT_DIR',
            '-i USER_LIST_FILE',
            '--encoding ENCODING',
            '--expand-validation-with-affected-entities',
            '-D',
            '-n NEW_OWNER',
            '-x'
        ]

        r = self.execute_anonymizer('anonymize -c {} {} --info'.format(config_file.name, ' '.join(cmdline_params)))
        std_out = r.stdout.decode('utf-8')
        # decoded_stderr = r.stderr.decode('utf-8')
        # print("r.returncode {}".format(r.returncode))
        # print("r.stderr {}".format(decoded_stderr))
        # print("r.stdout {}".format(decoded_stdout))

        expected_config_as_sorted_json = json.dumps(expected_config, sort_keys=True)
        got_config_as_sorted_json = json.dumps(
            json.loads(std_out.replace('Effective config:\n', '')), sort_keys=True)

        self.maxDiff = None
        self.assertEqual(expected_config_as_sorted_json, got_config_as_sorted_json)

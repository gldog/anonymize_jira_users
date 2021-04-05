import textwrap

from base_test_class import BaseTestClass


class TestAuth(BaseTestClass):

    def call_with_valid_auth_to_reset_failed_logins(self):
        valid_cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic admin:admin"'
        ]
        self.execute_anonymizer(' '.join(valid_cmd))

    def test_missing_base_url(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            # '-b', 'http://localhost:2990/jira',
            '-a', '"Basic admin:admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)

        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: Missing jira_base_url
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_missing_auth(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            # '-a', '"Basic admin:admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)

        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: Missing authentication
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_bad_url(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://in-va-lid:2990/jira',
            '-a', '"Basic admin:admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)

        expected_stderr = textwrap.dedent("""        usage: anonymize_jira_users.pyz anonymize [-h]
                                                  [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                  [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                  [-a ADMIN_USER_AUTH]
                                                  [-o REPORT_OUT_DIR]
                                                  [-i USER_LIST_FILE]
                                                  [--encoding ENCODING]
                                                  [--expand-validation-with-affected-entities]
                                                  [--info] [-n NEW_OWNER] [-x]
        anonymize_jira_users.pyz anonymize: error: HTTPConnectionPool(host='in-va-lid', port=2990):""")
        self.assertTrue(r.stderr.decode().startswith(expected_stderr), expected_stderr)

    def test_invalid_auth_format(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)

        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: validate_auth_parameter detected invalid format in authentication parameter.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_bad_auth_type(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"B-a-s-i-c admin:admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)
        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: validate_auth_parameter detected invalid authentication type 'B-a-s-i-c'. Expect 'Basic' or 'Bearer'.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_bad_username(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic b-a-d-min:admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)
        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: setup_http_session failed with 401 due to invalid credentials.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_bad_password(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic admin:b-a-d-min"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)
        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: setup_http_session failed with 401 due to invalid credentials.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_missing_password(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic admin:"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)
        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: setup_http_session failed with 401 due to invalid credentials.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)

    def test_missing_username(self):
        self.call_with_valid_auth_to_reset_failed_logins()
        cmd = [
            'anonymize',
            '-b', 'http://localhost:2990/jira',
            '-a', '"Basic :admin"',
            '-i', 'imaginary_user_list_file.cfg',
            '-n', 'imaginary-new-owner'
        ]
        r = self.execute_anonymizer(' '.join(cmd), is_log_output=True)
        self.assertEqual(2, r.returncode)
        expected_stderr = textwrap.dedent("""            usage: anonymize_jira_users.pyz anonymize [-h]
                                                      [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                                                      [-c CONFIG_FILE] [-b JIRA_BASE_URL]
                                                      [-a ADMIN_USER_AUTH]
                                                      [-o REPORT_OUT_DIR]
                                                      [-i USER_LIST_FILE]
                                                      [--encoding ENCODING]
                                                      [--expand-validation-with-affected-entities]
                                                      [--info] [-n NEW_OWNER] [-x]
            anonymize_jira_users.pyz anonymize: error: setup_http_session failed with 401 due to invalid credentials.
            """)
        self.assertEqual(r.stderr.decode(), expected_stderr)
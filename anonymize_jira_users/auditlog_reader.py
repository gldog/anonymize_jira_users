import re
from dataclasses import dataclass
from logging import Logger

from auditlog_iterator import AuditLogIterator
from config import Config
from execution_logger import ExecutionLogger
from jira import Jira
from jira_user import JiraUser


@dataclass
class AuditlogReader:
    config: Config
    log: Logger
    jira: Jira
    execution_logger: ExecutionLogger

    def get_anonymized_user_data_from_audit_log(self, user: JiraUser):
        """
        Get the anonymized user-data from the audit-log.

        Use either the deprecated audit-records API or the newer audit-events API, depending on the Jira-version.

        Atlassian introduced anonymization in Jira 8.7.
        The Anonymizer queries the anonymized user-data from the audit-log.

        Jira supports two auditing REST-APIs:

          1. GET /rest/api/2/auditing/record, deprecated since 8.12 (the older one).
              https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords
          2. "Audit log improvements for developers", introduced in 8.8 (the newer one).
              https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html

        A switch in this function get_anonymized_user_data_from_audit_log() delegates calls to
        one of these audit REST-APIs depending on the Jira-version:
        Until 8.9.x, the API 1) is used. For 8.10 and later, the new API 2) is used.

        Why is Jira 8.10 the border?

        In general, attributes could be an easy way to identify the content the Analyzer
        shall read. But the language used in parts of the audit-logs depends on the system
        default language
            1. at the time of the anonymization, and
            2. at the time of reading the audit logs.
        This affects also attributes. But if attributes occur in different languages it is not
        possible to identify them savely. A way for detecting the right information is needed
        independently from the language-settings at the time of the anonymization and at the
        time of requesting them.

        API 1):
        Until at least Jira 8.9.x the value of the attribute "summary" is always EN and is
        e. g. "User anonymized". Starting with Jira 8.10, the language of the value of "summary"
        depends on the system default language at the time of anonymization. E.g. in EN it is
        "User anonymized", but in DE it is "Benutzer anonymisiert". So the audit log entry
        containing the information of "User anonymized" could only be identified by the term
        "User anonymized" until Jira 8.9.x.

        API 2):
        Has i18n-keys. Unfortunately, these keys are not consistent across the Jira-versions.
        But starting with Jira 8.10, they can be used. See
        get_anonymized_user_data_from_audit_events() for more details.

        :param user: The user to search for in the audit-log
        """

        self.log.debug(f"for user '{user.name}' between anonymization_start_time {user.anonymization_start_time}"
                       f" and anonymization_finish_time {user.anonymization_finish_time}")

        # For the log.
        user.logs['anonymized_data_from_rest'] = {
            'user_name': None,
            'user_key': None,
            'display_name': None,
            # The description is for development and documentation, not to extract data.
            'description': None
        }
        anonymized_data = user.logs['anonymized_data_from_rest']

        user.logs['rest_auditing'] = {
            'doc': "The date in the URL-param is UTC.",
            'searched_pages': 0,
            'pages': {}
        }

        if self.jira.is_jira_version_less_then(8, 10):
            auditlog_iterator = AuditLogIterator(log=self.log, jira=self.jira,
                                                 execution_logger=self.execution_logger,
                                                 user_logger_rest_auditing=user.logs['rest_auditing'],
                                                 use_deprecated_records_api=True,
                                                 start_time=user.anonymization_start_time,
                                                 finish_time=user.anonymization_finish_time)
            self.get_anonymized_userdata_from_audit_records_for_user(user, auditlog_iterator, anonymized_data)
        else:
            auditlog_iterator = AuditLogIterator(log=self.log, jira=self.jira,
                                                 execution_logger=self.execution_logger,
                                                 user_logger_rest_auditing=user.logs['rest_auditing'],
                                                 start_time=user.anonymization_start_time,
                                                 finish_time=user.anonymization_finish_time)
            self.get_anonymized_userdata_from_audit_events_for_user(user, auditlog_iterator, anonymized_data)

        user.logs['rest_auditing']['searched_pages'] = auditlog_iterator.current_page_num + 1
        auditlog_iterator.clear_current_page()

    def get_anonymized_userdata_from_audit_events_for_user(self, user: JiraUser, auditlog_iterator, anonymized_data):

        for entry in auditlog_iterator:

            if user.is_anonymized_data_complete():
                break

            # try: Just a lifeline. It is expected all used keys are present.
            try:
                #
                # Get the anonymized user-name and user-key.
                #
                # actionI18nKey was added in Jira 8.10.

                if entry['type']['actionI18nKey'] == 'jira.auditing.user.anonymized':
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    for extra_attribute in entry['extraAttributes']:
                        # In Jira 8.10 the "nameI18nKey" was added.
                        # In Jira 8.10, 8.11, and 8.12 the key to look for is "description".
                        # Starting with Jira 8.13, it is
                        # "jira.auditing.extra.parameters.event.description".
                        # Note, these keys "description" and
                        # "jira.auditing.extra.parameters.event.description" are also used in the
                        # event with key "jira.auditing.user.anonymization.started", so that key
                        # is not unique. Therefore the path "event/type/actionI18nKey" is used to
                        # identify the event of interest.
                        # The jira.auditing.extra.parameters.event.long.description rarely cames up
                        # in my tests, but is also possible. See Jira-code
                        #   jira-project/jira-components/jira-core/src/main/java/com/atlassian/
                        #   jira/auditing/spis/migration/mapping/
                        #   AuditExtraAttributesConverter.java:
                        #   String EVENT_DESCRIPTION_I18N_KEY =
                        #       "jira.auditing.extra.parameters.event.description"
                        #   String EVENT_LONG_DESCRIPTION_I18N_KEY =
                        #       "jira.auditing.extra.parameters.event.long.description"
                        if extra_attribute['nameI18nKey'] in ['description',
                                                              'jira.auditing.extra.parameters.event.description',
                                                              'jira.auditing.extra.parameters.event.long.description']:
                            anonymized_data['description'] = extra_attribute['value']
                            # The 'value' is something like:
                            #   "User with username 'jirauser10104' (was: 'user4pre84') and key
                            #       >> 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                            # The parts of interest are 'jirauser10104', 'user4pre84',
                            # 'JIRAUSER10104', 'user4pre84'. All given in single quotes.
                            parts = re.findall(r"'(.*?)'", extra_attribute['value'])
                            anonymized_data['user_name'] = parts[0]
                            anonymized_data['user_key'] = parts[2]
                            user.anonymized_user_name = parts[0]
                            user.anonymized_user_key = parts[2]
                            break

                #
                # Get the anonymized user-display-name.
                #
                elif entry['type']['actionI18nKey'] == 'jira.auditing.user.updated':
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                    #
                    # The lang-setting (enUS, deDE) is the default system language at anonymizing.
                    #
                    # 8.10; enUS, deDE:
                    #             "changedValues": [
                    #                 {
                    #                     "key": "Email",
                    #                     "from": "User1Post84@example.com",
                    #                     "to": "JIRAUSER10401@jira.invalid"
                    #                 },
                    #                 {
                    #                     "key": "Full name",
                    #                     "from": "User 1 Post 84",
                    #                     "to": "user-04cab"
                    #                 }
                    #             ],
                    #
                    # 8.11, 8.12, 8.13; enUS, deDE:
                    #             "changedValues": [
                    #                 {
                    #                     "key": "Email",
                    #                     "i18nKey": "Email",
                    #                     "from": "User1Post84@example.com",
                    #                     "to": "JIRAUSER10401@jira.invalid"
                    #                 },
                    #                 {
                    #                     "key": "Full name",
                    #                     "i18nKey": "Full name",
                    #                     "from": "User 1 Post 84",
                    #                     "to": "user-04cab"
                    #                 }
                    #             ],
                    #
                    # 8.14, 8.15, 8.16, 8.17, 8.18, 8.19; enUS:
                    #             "changedValues": [
                    #                 {
                    #                     "key": "Email",
                    #                     "i18nKey": "common.words.email",
                    #                     "from": "User1Post84@example.com",
                    #                     "to": "JIRAUSER10401@jira.invalid"
                    #                 },
                    #                 {
                    #                     "key": "Full name",
                    #                     "i18nKey": "common.words.fullname",
                    #                     "from": "User 1 Post 84",
                    #                     "to": "user-04cab"
                    #                 }
                    #             ],
                    #
                    # 8.14, 8.15, 8.16, 8.17, 8.18, 8.19; deDE:
                    #             "changedValues": [
                    #                 {
                    #                     "key": "E-Mail",
                    #                     "i18nKey": "common.words.email",
                    #                     "from": "User1Post84@example.com",
                    #                     "to": "JIRAUSER10401@jira.invalid"
                    #                 },
                    #                 {
                    #                     "key": "Vollständiger Name",
                    #                     "i18nKey": "common.words.fullname",
                    #                     "from": "User 1 Post 84",
                    #                     "to": "user-04cab"
                    #                 }
                    #             ],
                    for changed_value in entry['changedValues']:
                        try:
                            # First look for the 'key' because it is always present. Then look for
                            # the 'i18nKey'. This could lead to a KeyError.
                            if not (changed_value['key'] == 'Full name'
                                    or changed_value['i18nKey'] == 'common.words.fullname'):
                                continue
                        except KeyError:
                            continue

                        # Found the entry with the renamed user-display-name.
                        anonymized_data['display_name'] = changed_value['to']
                        user.anonymized_user_display_name = changed_value['to']
                        break

            except KeyError:
                pass

    def get_anonymized_userdata_from_audit_records_for_user(self, user: JiraUser, auditlog_iterator, anonymized_data):
        """
        Until at least Jira 8.9.x the value of the attribute "summary" is always EN and is
        e. g. "User anonymized". Starting with Jira 8.10, the language of the value of "summary"
        depends on the system default language at the time of anonymization. E.g. in EN it is
        "User anonymized", but in DE it is "Benutzer anonymisiert". So the audit log entry
        containing the information of "User anonymized" could only be identified by the term
        "User anonymized" until Jira 8.9.x.

        :param user:
        :param auditlog_iterator:
        :param anonymized_data:
        :return:
        """

        for entry in auditlog_iterator:

            #
            # About the actions
            #
            # The order of actions after an anonymization is:
            #   1. record.summary: "User anonymization started"
            #   2. record.summary: "User updated"
            #   3. record.summary: "User's key changed"
            #   4. record.summary: "User renamed"
            #   5. record.summary: "User anonymized"
            #
            # The events are sorted by date descending. This means, the above actions come in the
            # order 5 to 1.
            #
            # We're looking here for the new user-name, the new user-key (if the user is
            # pre-Jira-8.4-user), and the new display-name. It is sufficient to look into
            # 'User renamed' and 'User updated' to get these data.
            #
            # Unfortunately, the summaries depend on the system-default-language. So we can't
            # check for them. We have to look in to the changedValues directly.
            #

            if user.is_anonymized_data_complete():
                break

            # try: Just a lifeline. It is expected all used keys are present..
            try:
                #
                # Get the anonymized user-name and user-key.
                #
                # Until Jira 8.9.x the summary is always EN and is "User anonymized". Starting with
                # Jira 8.10, the summary language depends on the system default language at the
                # of anonymization. E. g. in DE it is "Benutzer anonymisiert". But this
                # API "/rest/api/2/auditing/record" is used by the Anonymizer only for Jira-version
                # before 8.10.
                if entry['summary'] == 'User anonymized':
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    anonymized_data['description'] = entry['description']
                    # The 'description' is something like the following string and in EN:
                    #   "User with username 'jirauser10104' (was: 'user4pre84') and key
                    #       >> 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                    # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104',
                    # 'user4pre84'. All given in single quotes.
                    parts = re.findall(r"'(.*?)'", entry['description'])
                    anonymized_data['user_name'] = parts[0]
                    anonymized_data['user_key'] = parts[2]
                    user.anonymized_user_name = parts[0]
                    user.anonymized_user_key = parts[2]

                #
                # Get the anonymized user-display-name.
                #
                # Until at least Jira 8.9 the "summary" is always EN and is "User updated".
                elif entry['summary'] == 'User updated':
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    for changed_value in entry['changedValues']:
                        if changed_value['fieldName'] == 'Full name':
                            anonymized_data['display_name'] = changed_value['changedTo']
                            user.anonymized_user_display_name = changed_value['changedTo']
                            break

            except KeyError:
                pass

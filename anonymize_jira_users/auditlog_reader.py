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
        The language used in parts of the audit-logs depends on the system default language. This
        affects attributes. In general, attributes are an easy way to identify the content the
        Analyzer shall read. But if attributes occur in different languages this isn't possible.

        API 1): Until Jira 8.9.x the summary is always EN and is 'User anonymized'. Starting with
        Jira 8.10, the summary language depends on the system default language. E.g. in DE it is
        'Benutzer anonymisiert'.

        API 2) has i18n-keys. Unfortunately, these keys are not consistent across the Jira-versions.
        But starting with Jira 8.10, they can be used. See
        get_anonymized_user_data_from_audit_events() for more details.

        :param user: The user to search for in the audit-log
        """

        self.log.debug(f"for user '{user.name}' between anonymization_start_time {user.anonymization_start_time}"
                       f" and anonymization_finish_time {user.anonymization_finish_time}")

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

            if self.is_anonymized_userdata_complete_for_user(user):
                break

            try:
                # actionI18nKey was added in Jira 8.10.
                if entry['type']['actionI18nKey'] == 'jira.auditing.user.anonymized':
                    for extra_attribute in entry['extraAttributes']:
                        # In Jira 8.10 the 'nameI18nKey' was added.
                        # In Jira 8.10, 8.11, and 8.12 the key to look for is 'description'.
                        # Starting with Jira 8.13, it is
                        # 'jira.auditing.extra.parameters.event.description'.
                        # Note, these keys 'description' and
                        # 'jira.auditing.extra.parameters.event.description' are also used in the
                        # event with key 'jira.auditing.user.anonymization.started', so that key
                        # is not unique. Therefore the path 'event/type/actionI18nKey' is used to
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
                        key = extra_attribute['nameI18nKey']
                        if key in ['description',
                                   'jira.auditing.extra.parameters.event.description',
                                   'jira.auditing.extra.parameters.event.long.description']:
                            user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
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
                            if user.logs['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                                # This is a deleted user. There is no display-name to look for in
                                # subsequent logs.
                                break
                            else:
                                continue
            except KeyError:
                pass

            # Not each record has the changedValues, so use try/except.
            try:
                changed_values = entry['changedValues']
            except KeyError:
                continue

            display_name_to_search_for = \
                user.logs['rest_get_user__before_anonymization']['json']['displayName']
            for changed_value in changed_values:
                # Not all changedValues-entries have a 'from' and a 'to' key.
                try:
                    if str(changed_value['to']).lower().startswith('jirauser'):
                        # This is the changedValues-entry either for the user-name (jirauser12345)
                        # or the user-key (JIRAUSER12345).
                        continue
                    if str(changed_value['from']) == display_name_to_search_for:
                        user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                        # Found the changedValues-entry with the user-display-name.
                        # Note, this could be equal to the user-name. And in Jira < 8.4, the
                        # user-name could also be equal to the user-key.
                        anonymized_data['display_name'] = changed_value['to']
                        user.anonymized_user_display_name = changed_value['to']
                except KeyError:
                    continue

    def get_anonymized_userdata_from_audit_records_for_user(self, user: JiraUser, auditlog_iterator, anonymized_data):

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

            if self.is_anonymized_userdata_complete_for_user(user):
                break

            try:
                # Until Jira 8.9.x the summary is always EN and 'User anonymized'. Starting with
                # Jira 8.10, the summary language depends on the system default language. E. g.
                # in DE it is 'Benutzer anonymisiert'. But this API '/rest/api/2/auditing/record'
                # is used by the Anonymizer only for Jira-version before 8.10,
                # if record['summary'] == 'User anonymized':
                anonymized_data['description'] = entry['description']
                user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                # The 'description' is something like:
                #   "User with username 'jirauser10104' (was: 'user4pre84') and key 'JIRAUSER10104'
                #       >> (was: 'user4pre84') has been anonymized."
                # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104',
                # 'user4pre84'. All given in single quotes.
                parts = re.findall(r"'(.*?)'", entry['description'])
                anonymized_data['user_name'] = parts[0]
                anonymized_data['user_key'] = parts[2]
                user.anonymized_user_name = parts[0]
                user.anonymized_user_key = parts[2]
                if user.logs['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                    # This is a deleted user. There is no display-name to look for in subsequent
                    # logs.
                    break
                else:
                    continue
            except KeyError:
                pass

            # Not each record has the changesValues, so use try/except.
            try:
                changed_values = entry['changedValues']
            except KeyError:
                continue

            display_name_to_search_for = \
                user.logs['rest_get_user__before_anonymization']['json']['displayName']
            for changed_value in changed_values:
                # Not all changedValues-entries have a 'changedFrom' and a 'changedTo' key.
                try:
                    if str(changed_value['changedTo']).lower().startswith('jirauser'):
                        # This is the tuple either for the user-name (jirauser12345) or the
                        # user-key (JIRAUSER12345).
                        continue
                    if changed_value['changedFrom'] == display_name_to_search_for:
                        user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                        # Found the tuple with the user-display-name. This could be equal to the
                        # user-name. And in Jira < 8.4, the user-name could also be equal to the
                        # user-key.
                        anonymized_data['display_name'] = changed_value['changedTo']
                        user.anonymized_user_display_name = changed_value['changedTo']
                except KeyError:
                    continue

    def is_anonymized_userdata_complete_for_user(self, user: JiraUser):
        # TODO anonymized_data as parameter
        """Check if all three items user-name, -key, and display-name are collected so far.
         If so, we're done with this user.
         """

        anonymized_data = user.logs['anonymized_data_from_rest']
        is_complete = anonymized_data['user_name'] \
                      and anonymized_data['user_key'] \
                      and anonymized_data['display_name']
        self.log.debug(f"'{user.name}': {is_complete}. anonymized_data so far is {anonymized_data}")
        return is_complete

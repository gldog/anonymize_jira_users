import re
import time
from dataclasses import dataclass
from logging import Logger

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

        Use either the audit-records API or the newer audit-events API, depending on the Jira-version.

        :param user: The user to search for in the audit-log
        :return: None.
        """

        # Atlassian introduced anonymization in Jira 8.7.
        # The Anonymizer queries the anonymized user-data from the audit-log.
        #
        # Jira supports two auditing REST-APIs:
        #
        #   1. GET /rest/api/2/auditing/record, deprecated since 8.12.
        #       https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords
        #   2. "Audit log improvements for developers", introduced in 8.8.
        #       https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html
        #
        # A switch in this function delegates calls to the audit REST-APIs depending on the Jira-version:
        # Until 8.9.x, the API 1) is used. For 8.10 and later, the new API 2) is used.
        #
        # Why is Jira 8.10 the border?
        # The language used in parts of the audit-logs depends on the system default language. This affects
        # attributes. Attributes are an easy way to identify the content the Analyzer shall read. But if
        # attributes occur in different languages, this isn't possible.
        # API 1): Until Jira 8.9.x the summary is always EN and 'User anonymized'. Starting with Jira 8.10, the
        # summary language depends on the system default language. E.g. in DE it is 'Benutzer anonymisiert'.
        # API 2) has i18n-keys. These keys are not consistent across the Jira-versions. But starting with Jira 8.10,
        # they can be used. See get_anonymized_user_data_from_audit_events() for more details.
        #
        # Reading the audit-log user by user, or for all users in one go?
        # Collecting the anonymized user-data could also be done in one go after all users have been
        # anonymized. But that is not as easy as it sounds: Both APIs are limited in output. the API 1) is
        # limited to 1.000 records, and the API 2) is paged with a default of 200 events/page. That could
        # be fiddly. I'm confident there is not really a downside in execution-time if the anonymized
        # data is called for each user one by one.
        if self.jira.is_jira_version_less_then(8, 10):
            self.get_anonymized_userdata_from_audit_records(user)
        else:
            self.get_anonymized_userdata_from_audit_events_for_user(user)

    def get_anonymized_userdata_from_audit_events_for_user(self, user: JiraUser):
        anonymization_start_date = user.logs['rest_post_anonymization']['json']['submittedTime']
        anonymization_start_date_utc = self.date_str_to_utc_str(anonymization_start_date)
        self.log.debug(
            f"anonymization_start_date: local {anonymization_start_date}, UTC {anonymization_start_date_utc}")

        user.logs['rest_auditing'] = {'doc': "The date in the URL-param is UTC."}
        user.logs['rest_auditing'].update({'entries_after_seconds_msg': ''})

        # Jira writes the audit log entries asynchronously. It is unclear how long this takes.
        waited_seconds_so_far = 0
        intervals_seconds = [1, 2, 2, 5, 5]
        # To suppress PyCharm-message "Local variable 'r' might be referenced before assignment".
        r = {}
        audit_entry_count = 0
        for interval in intervals_seconds:
            time.sleep(interval)
            waited_seconds_so_far += interval
            # Include the from-date, to not include e.g. previous renamings which has nothing to
            # do with the anonymization, and to limit the amount of response-data. The date must
            # be given in UTC with format "2020-12-30T13:53:17.996Z". The response-JSON is sorted
            # by date descending.
            r = self.jira.get_audit_events_since(anonymization_start_date_utc)
            r.raise_for_status()
            audit_entry_count = r.json()['pagingInfo']['size']
            message = f"Got audit log entries after {waited_seconds_so_far} seconds: {audit_entry_count}."
            self.log.info(message + " TODO: This will become a DEBUG level message.")
            user.logs['rest_auditing']['entries_after_seconds_msg'] = message
            if audit_entry_count > 0:
                break

        if audit_entry_count > 0:
            user.logs['rest_auditing'].update({'request': Jira.serialize_response(r)})
            auditing_events = r.json()
        else:
            error_message = f"{user.name}: The GET {r.request.url} didn't return any audit log entry" \
                            f" within {waited_seconds_so_far} seconds." \
                            " No anonymized user-name/key/display-name could be retrieved."
            self.log.error(error_message)
            self.execution_logger.logs['errors'].append(error_message)
            return

        user.logs['anonymized_data_from_rest'] = {
            'user_name': None,
            'user_key': None,
            'display_name': None,
            # The description is more for development and documentation, not to extract data in advance.
            'description': None
        }
        anonymized_data = user.logs['anonymized_data_from_rest']

        for entity in auditing_events['entities']:

            #
            # Similar to get_anonymized_user_data_from_audit_records()
            #

            if self.is_anonymized_userdata_complete_for_user(user):
                break

            try:
                # actionI18nKey was added in Jira 8.10.
                if entity['type']['actionI18nKey'] == 'jira.auditing.user.anonymized':
                    for extra_attribute in entity['extraAttributes']:
                        # In Jira 8.10 the 'nameI18nKey' was added.
                        # In Jira 8.10, 8.11, and 8.12 the key to look for is 'description'.
                        # Starting with Jira 8.13, it is 'jira.auditing.extra.parameters.event.description'
                        # Note, these keys 'description' and 'jira.auditing.extra.parameters.event.description' are
                        # also used in the event with key 'jira.auditing.user.anonymization.started', so that key is
                        # not unique. Therefore the path 'event/type/actionI18nKey' is used to identify the event
                        # of interest.
                        # The jira.auditing.extra.parameters.event.long.description rarely came up in my tests, but
                        # is also possible. See Jira-code
                        #   jira-project/jira-components/jira-core/src/main/java/com/atlassian/jira/auditing/spis/
                        #       migration/mapping/AuditExtraAttributesConverter.java:
                        #   String EVENT_DESCRIPTION_I18N_KEY = "jira.auditing.extra.parameters.event.description"
                        #   String EVENT_LONG_DESCRIPTION_I18N_KEY = "jira.auditing.extra.parameters.event.long.description"
                        key = extra_attribute['nameI18nKey']
                        if key in ['description',
                                   'jira.auditing.extra.parameters.event.description',
                                   'jira.auditing.extra.parameters.event.long.description']:
                            anonymized_data['description'] = extra_attribute['value']
                            # The 'value' is something like:
                            #   "User with username 'jirauser10104' (was: 'user4pre84') and key 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                            # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104', 'user4pre84'.
                            # All given in single quotes.
                            parts = re.findall(r"'(.*?)'", extra_attribute['value'])
                            anonymized_data['user_name'] = parts[0]
                            anonymized_data['user_key'] = parts[2]
                            user.anonymized_user_name = parts[0]
                            user.anonymized_user_key = parts[2]
                            if user.logs['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                                # This is a deleted user. There is no display-name to look for in subsequent logs.
                                break
                            else:
                                continue
            except KeyError:
                pass

            # Not each record has the changedValues, so use try/except.
            try:
                changed_values = entity['changedValues']
            except KeyError:
                continue

            display_name_to_search_for = user.logs['rest_get_user__before_anonymization']['json']['displayName']
            for changed_value in changed_values:
                # Not all changedValues-entries have a 'from' and a 'to' key.
                try:
                    if str(changed_value['to']).lower().startswith('jirauser'):
                        # This is the changedValues-entry either for the user-name (jirauser12345) or
                        # the user-key (JIRAUSER12345).
                        continue
                    if changed_value['from'] == display_name_to_search_for:
                        # Found the changedValues-entry with the user-display-name.
                        # Note, this could be equal to the user-name. And in Jira < 8.4, the user-name could also be equal
                        # to the user-key.
                        anonymized_data['display_name'] = changed_value['to']
                        user.anonymized_user_display_name = changed_value['to']
                except KeyError:
                    continue

    def get_anonymized_userdata_from_audit_records(self, user: JiraUser):
        # user_name_to_search_for = user.name

        anonymization_start_date = user.logs['rest_post_anonymization']['json']['submittedTime']
        anonymization_start_date_utc = self.date_str_to_utc_str(anonymization_start_date)
        self.log.debug(
            f"anonymization_start_date: local {anonymization_start_date}, UTC {anonymization_start_date_utc}")

        user.logs['rest_auditing'] = {'doc': "The date in the URL-param is UTC."}
        user.logs['rest_auditing'].update({'entries_after_seconds_msg': ''})

        # Jira writes the audit log entries asynchronously. It is unclear how long this takes. Try immediately after
        # the anonymization to read team. If the count of audit logs is 0, wait the seconds goven as list in the
        # following for-loop.
        waited_seconds_so_far = 0
        intervals_seconds = [1, 2, 2, 5, 5]
        # To suppress: Local variable 'r' might be referenced before assignment.
        r = {}
        audit_entry_count = 0
        for interval in intervals_seconds:
            time.sleep(interval)
            waited_seconds_so_far = 0
            waited_seconds_so_far += interval
            # Include the from-date, to not include e.g. previous renamings which has nothing to
            # do with the anonymization, and to limit the amount of response-data. The date must
            # be given in UTC with format "2020-12-30T13:53:17.996Z". The response-JSON is sorted
            # by date descending.
            r = self.jira.get_audit_records_since(anonymization_start_date_utc)
            r.raise_for_status()
            audit_entry_count = len(r.json()['records'])
            message = f"Got audit log entries after {waited_seconds_so_far} seconds: {audit_entry_count}."
            self.log.info(message + " TODO: This will become a DEBUG level message.")
            user.logs['rest_auditing']['entries_after_seconds_msg'] = message
            if audit_entry_count > 0:
                break

        if audit_entry_count > 0:
            user.logs['rest_auditing'].update({'request': Jira.serialize_response(r)})
            auditing_records = r.json()
        else:
            error_message = f"{user.name}: The GET {r.request.url} didn't return any audit log entry" \
                            f" within {waited_seconds_so_far} seconds." \
                            " No anonymized user-name/key/display-name could be retrieved."
            self.log.error(error_message)
            self.execution_logger.logs['errors'].append(error_message)
            return

        user.logs['anonymized_data_from_rest'] = {
            'user_name': None,
            'user_key': None,
            'display_name': None,
            # The description is more for development and documentation, not to extract data in advance.
            'description': None
        }
        anonymized_data = user.logs['anonymized_data_from_rest']

        for record in auditing_records['records']:
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
            # The events are sorted by date descending. This means, the above actions come in the order 5 to 1.
            #
            # We're looking here for the new user-name, the new user-key (if the user is pre-Jira-8.4-user), and
            # the new display-name. It is sufficient to look into 'User renamed' and 'User updated' to get these data.
            #
            # Unfortunately, the summaries depend on the system-default-language. So we can't check for them. We
            # have to look in to the changedValues directly.
            #

            if self.is_anonymized_userdata_complete_for_user(user):
                break

            try:
                # Until Jira 8.9.x the summary is always EN and 'User anonymized'. Starting with
                # Jira 8.10, the summary language depends on the system default language. E. g.
                # in DE it is 'Benutzer anonymisiert'. But this API '/rest/api/2/auditing/record'
                # is used by the Anonymizer only for Jira-version before 8.10,
                # if record['summary'] == 'User anonymized':
                anonymized_data['description'] = record['description']
                # The 'description' is something like:
                #   "User with username 'jirauser10104' (was: 'user4pre84') and key 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104', 'user4pre84'.
                # All given in single quotes.
                parts = re.findall(r"'(.*?)'", record['description'])
                anonymized_data['user_name'] = parts[0]
                anonymized_data['user_key'] = parts[2]
                user.anonymized_user_name = parts[0]
                user.anonymized_user_key = parts[2]
                if user.logs['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                    # This is a deleted user. There is no display-name to look for in subsequent logs.
                    break
                else:
                    continue
            except KeyError:
                pass

            # Not each record has the changesValues, so use try/except.
            try:
                changed_values = record['changedValues']
            except KeyError:
                continue

            display_name_to_search_for = user.logs['rest_get_user__before_anonymization']['json']['displayName']
            for changed_value in changed_values:
                # Not all changedValues-entries have a 'changedFrom' and a 'changedTo' key.
                try:
                    if str(changed_value['changedTo']).lower().startswith('jirauser'):
                        # This is the tuple either for the user-name (jirauser12345) or the user-key (JIRAUSER12345).
                        continue
                    if changed_value['changedFrom'] == display_name_to_search_for:
                        # Found the tuple with the user-display-name. This could be equal to the user-name. And in
                        # Jira < 8.4, the user-name could also be equal to the user-key.
                        anonymized_data['display_name'] = changed_value['changedTo']
                        user.anonymized_user_display_name = changed_value['changedTo']
                except KeyError:
                    continue

    def is_anonymized_userdata_complete_for_user(self, user: JiraUser):
        """Check if all three items user-name, -key, and display-name are collected so far.
         If so, we're done with this user.
         """

        anonymized_data = user.logs['anonymized_data_from_rest']
        is_complete = anonymized_data['user_name'] \
                      and anonymized_data['user_key'] \
                      and anonymized_data['display_name']
        self.log.debug(f"{is_complete}. anonymized_data for user '{user.name}' so far is {anonymized_data}")
        return is_complete

    @staticmethod
    def date_str_to_utc_str(date_str):
        """Convert date/time-string of format "2020-12-29T23:17:35.399+0100" to UTC in format 2020-12-29T23:16:35.399Z.

        :param date_str: Expect format "2020-12-29T23:17:35.399+0100"
        :return: String UTC in format 2020-12-29T23:16:35.399Z
        """
        # Split string in "2020-12-29T23:17:35" and ".399+0100".
        date_parts = date_str.split('.')
        # Convert to UTC. The conversion respects DST.
        date_utc = time.strftime("%Y-%m-%dT%H:%M:%S",
                                 time.gmtime(time.mktime(time.strptime(date_parts[0], '%Y-%m-%dT%H:%M:%S'))))
        date_utc += f'.{date_parts[1][:3]}Z'
        return date_utc

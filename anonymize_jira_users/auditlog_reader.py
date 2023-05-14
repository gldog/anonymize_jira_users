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
    """For details about the event-APIs see dev/auditlog_reader.md. """

    # TODO Remove config
    config: Config
    log: Logger
    jira: Jira
    execution_logger: ExecutionLogger

    def get_anonymized_user_data_from_audit_log(self, user: JiraUser):

        self.log.debug(f"for user '{user.name}' between anonymization_start_time {user.anonymization_start_time}"
                       f" and anonymization_finish_time {user.anonymization_finish_time}")

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
            self.get_anonymized_userdata_from_audit_records_for_user(user, auditlog_iterator)
        else:
            auditlog_iterator = AuditLogIterator(log=self.log, jira=self.jira,
                                                 execution_logger=self.execution_logger,
                                                 user_logger_rest_auditing=user.logs['rest_auditing'],
                                                 start_time=user.anonymization_start_time,
                                                 finish_time=user.anonymization_finish_time)
            self.get_anonymized_userdata_from_audit_events_for_user(user, auditlog_iterator)

        user.logs['rest_auditing']['searched_pages'] = auditlog_iterator.current_page_num + 1
        auditlog_iterator.clear_current_page()

    def get_anonymized_userdata_from_audit_events_for_user(self, user: JiraUser, auditlog_iterator):

        for entry in auditlog_iterator.entries():

            if user.is_anonymized_data_complete():
                break

            #
            # Get the anonymized user-name and user-key.
            #

            # actionI18nKey was added in Jira 8.10.
            if entry['type']['actionI18nKey'] == 'jira.auditing.user.anonymized':
                # Check for the anonymized user in this entry. It is expected this is the right one because only one
                # anonymization at time is possible and the Anonymizer requests the audit-logs just between
                # anonymization-start- and end-time. But just to be sure.
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
                        # The 'value' is something like:
                        #   "User with username 'jirauser10104' (was: 'user4pre84') and key
                        #       >> 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                        # The parts of interest are 'jirauser10104', 'user4pre84',
                        # 'JIRAUSER10104', 'user4pre84'. All given in single quotes.
                        # parts = re.findall(r"'(.*?)'", extra_attribute['value'])
                        #
                        # This line is generated from:
                        #
                        # JiraWebActionSupport.properties:
                        # jira.auditing.user.anonymized.description=User with username ''{0}'' (was: ''{1}'') and key ''{2}'' (was: ''{3}'') has been anonymized.
                        parts = parse_anonymization_summary(extra_attribute['value'])

                        current_user_name = parts[1]

                        # Check for the expected user: It is expected this is the right entry one because only one
                        # anonymization at time is possible and the Anonymizer requests the audit-logs just between
                        # anonymization-start- and end-time. But just to be sure.
                        if current_user_name == user.name:
                            user.anonymized_user_key = parts[2]
                            user.anonymized_user_name = parts[0]
                            break

            #
            # Get the anonymized user-display-name.
            #
            elif entry['type']['actionI18nKey'] == 'jira.auditing.user.updated':
                user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                # Check for the expected user: It is expected this is the right entry one because only one
                # anonymization at time is possible and the Anonymizer requests the audit-logs just between
                # anonymization-start- and end-time. But just to be sure.
                found_expected_user_name = False
                for affectedObject in entry['affectedObjects']:
                    if affectedObject['name'] == user.name:
                        found_expected_user_name = True
                        break

                if found_expected_user_name:

                    #
                    # The lang-setting (enUS, deDE) is the system default language at anonymizing (not at requesting
                    #                     # nor the lang-setting of the rquesting user).
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
                            # the 'i18nKey'. The latter could lead to a KeyError.
                            if not (changed_value['key'] == 'Full name'
                                    or changed_value['i18nKey'] == 'common.words.fullname'):
                                continue
                        except KeyError:
                            continue

                        # Found the entry with the renamed user-display-name.
                        user.anonymized_user_display_name = changed_value['to']
                        break

        self.set_values_for_non_anonymized_items(user)

    def get_anonymized_userdata_from_audit_records_for_user(self, user: JiraUser, auditlog_iterator):

        for entry in auditlog_iterator.entries():

            if user.is_anonymized_data_complete():
                break

            #
            # Get the anonymized user-name and user-key.
            #
            if entry['summary'] == 'User anonymized':
                user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                parts = parse_anonymization_summary(entry['description'])

                # Check for the expected user: It is expected this is the right entry one because only one
                # anonymization at time is possible and the Anonymizer requests the audit-logs just between
                # anonymization-start- and end-time. But just to be sure.
                current_user_name = parts[1]
                if current_user_name == user.name:
                    user.anonymized_user_name = parts[0]
                    user.anonymized_user_key = parts[2]

            #
            # Get the anonymized user-display-name.
            #
            # Until at least Jira 8.9 the "summary" is always EN and is "User updated".
            elif entry['summary'] == 'User updated':
                user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                # Check for the expected user: It is expected this is the right entry one because only one
                # anonymization at time is possible and the Anonymizer requests the audit-logs just between
                # anonymization-start- and end-time. But just to be sure.
                if entry['objectItem']['name'] == user.name:
                    for changed_value in entry['changedValues']:
                        if changed_value['fieldName'] == 'Full name':
                            user.anonymized_user_display_name = changed_value['changedTo']
                            break

        self.set_values_for_non_anonymized_items(user)

    def set_values_for_non_anonymized_items(self, user):
        # If there was no entry for name, key, or display name in the audit-logs, the item was not
        # changed. Keep the original as anonymized item.
        # But there is one exception: If a user was deleted. In that case, Jira TODO
        if not user.anonymized_user_name:
            user.anonymized_user_name = user.name
            self.log.info(f"hasen't found the anonymized user-name for user '{user.name}'"
                          f" in the audit-log. Kept the name '{user.name}' ")
        if not user.anonymized_user_key:
            user.anonymized_user_key = user.key
            # Do not print the following message. Users created in Jira-versions >= 8.4
            # have keys of format JIRAUSER12345, and those keys won't be anonymized.
            # The following message would be printed for all users created >= 8.4.
            # self.log.info(f"hasn't found the anonymized user-key for user '{user.name}'"
            #              f" in the audit-log. Kept the key '{user.key}' ")
        if not user.anonymized_user_display_name:
            user.anonymized_user_display_name = user.display_name
            self.log.info(f"hasen't found the anonymized user-display-name for user '{user.name}'"
                          f" in the audit-log. Kept the display-name '{user.display_name}' ")

        # Set user-name and -display-name to the user-key for deleted users. This is how the
        # REST API /rest/api/2/user behaves.
        #
        #   User User7Pre84:
        #
        #       Before deletion:
        #           user-name:      User7Pre84
        #           user-key:       user7pre84
        #           display-name:   User 7 Pre 84
        #       After deletion:
        #           user-name:      user7pre84          <-- now in lower case
        #           user-key:       user7pre84
        #           display-name:   user8post84
        #       After anonymization:
        #           user-name:      jirauser10109       <-- lower case
        #           user-key:       JIRAUSER10109
        #           display-name:   jirauser10109
        #
        #   User User8Post84:
        #
        #       Before deletion:
        #           user-name:      User8Post84
        #           user-key:       JIRAUSER10400
        #           display-name:   User 8 Post 84
        #       After deletion:
        #           user-name:      user8post84         <-- now in lower case
        #           user-key:       JIRAUSER10400
        #           display-name:   user8post84
        #       After anonymization:
        #           user-name:      jirauser10400       <-- lower case
        #           user-key:       JIRAUSER10400
        #           display-name:   jirauser10400
        #
        if user.deleted is True:
            # The anonymized user-key is in upper case JIRAUSER12345, but the user-name shall be
            # in lower case.
            user.anonymized_user_name = user.anonymized_user_key.lower()
            user.anonymized_user_display_name = user.anonymized_user_name


def parse_anonymization_summary(summary):
    """Parse the anonymization summary and return a tuple with:
        - [0]: the anonymized user-name
        - [1]: the user-name before anonymization
        - [2]: the anonymized user-key
        - [3]: the user-key before anonymization

    The summary is something like the following string and always in EN:

       "User with username 'jirauser10104' (was: 'user4pre84') and key
           >> 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."

    The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104',
    'user4pre84'. All given in single quotes.
    """
    parts = re.findall(r"User with username "
                       "'(.+?)' \(was: '(.+?)'\) and key '(.+?)' \(was: '(.+?)'\)"
                       " has been anonymized.",
                       summary)

    # An easier regex would be a more general one finding all strings within single quotes:
    #   parts = re.findall(r"'(.*?)'", entry['description'])
    # But this regex would not work for names containing a single quote in it, which is a legal
    # character for Jira user-names.

    #  re.findall() returns a list with one tuple. The list is not of interest, return just the tuple.
    return parts[0]

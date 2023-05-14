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
    # TODO Remove config
    config: Config
    log: Logger
    jira: Jira
    execution_logger: ExecutionLogger

    def get_anonymized_user_data_from_audit_log(self, user: JiraUser):
        """
        Get the anonymized user-data from the audit-log.

        Atlassian introduced anonymization in Jira 8.7.
        The Anonymizer queries the anonymized user-data from the audit-log.
        It uses either the deprecated audit-records API or the new audit-events API, depending on the
        Jira-version.

        Jira supports two auditing REST-APIs:
          1. GET /rest/api/2/auditing/record, deprecated since 8.12 (the old one).
              https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords
          2. "Audit log improvements for developers", introduced in 8.8 (the new one).
              https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-1019401815.html

        A switch in this function get_anonymized_user_data_from_audit_log() delegates calls to
        one of these audit REST-APIs depending on the Jira-version:
        Until 8.9.x, the old API 1) is used. For 8.10 and later, the new API 2) is used.

        Investigated Jira-versions from 8.7 to 8.19.

        The data in the responses depends on:

            1. Jira-version.
                1.1 /rest/api/2/auditing/record:
                    Until 8.9, the summary is always in EN:
                        "summary": "User anonymized"
                    Starting with 8.10, the summary depends on the system default lang. E.g. if
                    the setting is DE, the summary is:
                        "summary": "Benutzer anonymisiert"
                1.2 /rest/auditing/1.0/events.
                    Evolved over time. In 8.10 i18n-keys were introduced, but were not present in
                    all objects from the beginning.

                    Version     JSON-path                       Lang     example
                    8.10        type.actionI18nKey              All     "jira.auditing.user.anonymized"
                    8.11        changedValues[n].i18nKey        All     "Full name"
                    8.13        extraAttributes[n].nameI18nKey  All         *1), =>
                                            before:
                                                "description"
                                            since 8.13:
                                                "jira.auditing.extra.parameters.event.description"
                    8.14        changedValues[n].i18nKey        All         =>
                                            before:
                                                "Full name"
                                            since 8.14:
                                                "common.words.fullname
                    8.15 - 8.19 no structure changes.

                    Re 1):
                    In addition to jira.auditing.extra.parameters.event.description there is also the
                    jira.auditing.extra.parameters.event.long.description. This rarely came up
                    in my tests, but is also possible. See Jira-code
                    jira-project/jira-components/jira-core/src/main/java/com/atlassian/
                        jira/auditing/spis/migration/mapping/AuditExtraAttributesConverter.java:
                            String EVENT_DESCRIPTION_I18N_KEY =
                                "jira.auditing.extra.parameters.event.description"
                            String EVENT_LONG_DESCRIPTION_I18N_KEY =
                                "jira.auditing.extra.parameters.event.long.description"

            2. API: /rest/api/2/auditing/record or /rest/auditing/1.0/events.
                The structure of the responses are different.

            3. System default language at anonymization.
                See 1.

            4. Languange setting at the time of the request of the anonymizing admin.

            5. Jira-version the anonymized user was created: <8.4 or >=8.4.

            6. Jira user-name format: If the username looks like an anonymized user like
                jirauser12345 or not.

                In case the user-name is of format username12345, the user-name and the user-key
                won't be anonymized. It seems Jira "thinks" those user has been anonymized.

            7. If the user was already anonymized.


        Why is Jira 8.10 the border?
            - In the API /rest/api/2/auditing/record until 8.9 the summary is always in EN.
            - In the API /rest/auditing/1.0/events since 8.10 the i18n-keys can be used.

        The functions get_anonymized_userdata_from_audit_records_for_user() and
        get_anonymized_userdata_from_audit_events_for_user() works in the following way:
        They look for a) the anonymized user-name, b) the anonymized user-key, and c) the anonymized
        user-display-name. For each of them: If not found it is assumed to not have been
        anonymized and the un-anonymized value is taken.

        :param user: The user to search for in the audit-log
        """

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

        #
        # About the events
        #
        # The order of events after an anonymization is:
        #   1. type actionI18nKey: "jira.auditing.user.anonymization.started"
        #   2. type actionI18nKey: "jira.auditing.user.updated"
        #   3. type actionI18nKey: "jira.auditing.user.key.changed"
        #   4. type actionI18nKey: "jira.auditing.user.renamed"
        #   5. type actionI18nKey: "jira.auditing.user.anonymized"
        #
        # In the REST response the events are sorted by date descending. The above events come in the order 5 to 1.
        #
        # Jira allows anonymizing an already anonymized user. In this case only 1 und 5 are
        # present (in the order 5, 1)
        #
        # A special case is anonymizing a user that looks like an anonymized user. E.g. the
        # user with name jirauser12345. But this is just the name set at user-creation.
        #
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
                # current_name = ''
                # for affectedObject in entry['affectedObjects']:
                #    current_name = affectedObject['name']
                #    if current_name == user.name:
                #        break
                # if current_name != user.name:
                #    self.log.warning(f"Saw unexpected user '{current_name}' in audit log event entry"
                #                     f" 'jira.auditing.user.anonymized'. Expected '{user.name}'")
                #    continue

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
        """
        Until at least Jira 8.9.x the value of the attribute "summary" is always EN and is
        e.g. "User anonymized". Starting with Jira 8.10, the language of the value of "summary"
        depends on the system default language at the time of anonymization. E.g. in EN it is
        "User anonymized", but in DE it is "Benutzer anonymisiert". So the audit log entry
        containing the information of "User anonymized" could only be identified by the term
        "User anonymized" until Jira 8.9.x.
        """

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
        # In the REST response the actions are ordered by date descending: The above actions come in the order 5 to 1.
        #
        # Jira allows anonymizing an already anonymized user. In this case only 1 und 5 are
        # present (in the order 5, 1)
        #
        # A special case is anonymizing a user that looks like an anonymized user. E.g. the
        # user with name jirauser12345.
        #
        for entry in auditlog_iterator.entries():

            if user.is_anonymized_data_complete():
                break

            #
            # Get the anonymized user-name and user-key.
            #
            # Until Jira 8.9.x the summary is always EN and is "User anonymized". Starting with
            # Jira 8.10, the summary language depends on the system default language at the
            # of anonymization. E.g. in DE it is "Benutzer anonymisiert". But this
            # API "/rest/api/2/auditing/record" is used by the Anonymizer only for Jira-version
            # before 8.10.
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

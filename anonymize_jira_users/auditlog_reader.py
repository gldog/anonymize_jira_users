import json
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

        Use either the deprecated audit-records API or the newer audit-events API, depending on the
        Jira-version.

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

        Investigated Jira-versions from 8.7 to 8.19.

        The data in the responses depends on:

            1. Jira-version.
                1.1 /rest/api/2/auditing/record:
                    Until 8.9, the summary is always in EN:
                        "summary": "User anonymized"
                    Starting with 8.10, the summary depends on the system default lang. E.g. if
                    the setting was DE, the summary is:
                        "summary": "Benutzer anonymisiert"
                1.2 /rest/auditing/1.0/events.
                    Evolved over time. in 8.10 i18n-keys were introduced, but were not present in
                    all objects.

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
                    In additin to jira.auditing.extra.parameters.event.description there is also the
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
        # In the REST response the events are sorted by date descending. This means, the above
        # events come in the order 5 to 1.
        #
        # Jira allows anonymizing an already anonymized user. In this case only 1 und 5 are
        # present (in the order 5, 1)
        #
        # A special case is anonymizing a user that looks like an anonymized user. E. g. the
        # user with name jirauser12345. But this is just the name set at user-creation.
        #
        for entry in auditlog_iterator.entries():

            if user.is_anonymized_data_complete():
                break

            #
            # Get the anonymized user-name.
            #
            if entry['type']['actionI18nKey'] == 'jira.auditing.user.renamed':
                # try/except: Check for expected format.
                try:
                    # Expect only one entry.
                    for changed_value in entry['changedValues']:
                        if changed_value['from'] == user.name:
                            user.anonymized_user_name = changed_value['to']
                            user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                except KeyError:
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    self.log.error(
                        f"'{user.name}' couldn't read the user-name '{user.name}' or the"
                        " anonymized user-name because the expected format of the audit log "
                        " format has changed. Expect the 'changedValues' with 'from'-key and"
                        f" 'to'-key. The current audit entry is: {json.dumps(entry)}")

            #
            # Get the anonymized user-key.
            #
            elif entry['type']['actionI18nKey'] == 'jira.auditing.user.key.changed':
                # try/except: Check for expected format.
                try:
                    # Expect only one entry.
                    for changed_value in entry['changedValues']:
                        if changed_value['from'] == user.key:
                            user.anonymized_user_key = changed_value['to']
                            user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                except KeyError:
                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    self.log.error(
                        f"'{user.name}' couldn't read the user-key '{user.key}' or the"
                        " anonymized user-key because the expected format of the audit log "
                        " format has changed. Expect the 'changedValues' with 'from'-key and"
                        f" 'to'-key. The current audit entry is: {json.dumps(entry)}")

            #
            # Get the anonymized user-display-name.
            #
            elif entry['type']['actionI18nKey'] == 'jira.auditing.user.updated':
                # There can be other 'jira.auditing.user.updated' events then for the anonymized
                # user. This is the case if some other user's e.g. display-name is renamed
                # during anonymization.
                # Check if this entry is for the anonymized user.
                # The affectedObjects contains exact one list-entry and the key "name". Checked
                # in Jira 8.10 - 8.19.
                # TODO Format-check.
                if entry['affectedObjects'][0]['name'] != user.name:
                    continue

                user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                #
                # The changedValues content changed over time. The following data shows the
                # contents for the Jira-versions and the system default languages.
                # The lang-setting (enUS, deDE) is the system default language at anonymizing
                # time (not at requesting time nor the lang-setting of the rquesting user).
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
                #
                for changed_value in entry['changedValues']:
                    try:
                        # First look for the 'key' because it is always present. But the key is
                        # onyl the fixed value 'Full name' until before 8.14. If the key is not
                        # 'Full name', it is expected there is the i18nKey with value
                        # 'common.words.fullname'.
                        #
                        #   key             i18nKey                 continue with
                        #                                           next entry
                        #  --------------+------------------------+-----------
                        #   'Full name'     KeyError                    No
                        #   'Full name'     'common.words.fullname'     No
                        #   other           KeyError                    Yes
                        #   other           'common.words.fullname'     No
                        #
                        if not (changed_value['key'] == 'Full name'
                                or changed_value['i18nKey'] == 'common.words.fullname'):
                            continue
                    except KeyError:
                        continue

                    # Found the entry with the renamed user-display-name.
                    anonymized_data['display_name'] = changed_value['to']
                    user.anonymized_user_display_name = changed_value['to']
                    break

        self.set_original_values_for_non_anonymized_values(user)

    def get_anonymized_userdata_from_audit_records_for_user(self, user: JiraUser, auditlog_iterator, anonymized_data):
        """
        Until at least Jira 8.9.x the value of the attribute "summary" is always EN and is
        e. g. "User anonymized". Starting with Jira 8.10, the language of the value of "summary"
        depends on the system default language at the time of anonymization. E.g. in EN it is
        "User anonymized", but in DE it is "Benutzer anonymisiert". So the audit log entry
        containing the information of "User anonymized" could only be identified by the term
        "User anonymized" until Jira 8.9.x.
        """

        lower_case_user_name = user.name.lower()

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
        # In the REST response the actions are sorted by date descending. This means, the above
        # actions come in the order 5 to 1.
        #
        # Jira allows anonymizing an already anonymized user. In this case only 1 und 5 are
        # present (in the order 5, 1)
        #
        # A special case is anonymizing a user that looks like an anonymized user. E. g. the
        # user with name jirauser12345.
        #
        # There are no format checks with try/except as in
        # get_anonymized_userdata_from_audit_events_for_user() because the audit-record-API is used
        # only until before 8.10, and the format is well-known and won't change.
        for entry in auditlog_iterator.entries():

            if user.is_anonymized_data_complete():
                break

            # try: Just a lifeline. It is expected all used keys are present..
            try:
                #
                # Get the anonymized user-name.
                #
                if entry['summary'] == 'User renamed':
                    for changed_value in entry['changedValues']:
                        if changed_value['changedFrom'] == user.name:
                            anonymized_data['user_name'] = changed_value['changedTo']
                            user.anonymized_user_name = changed_value['changedTo']
                            user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                #
                # Get the anonymized user-key.
                #
                elif entry['summary'] == 'User\'s key changed':
                    # Don't know if there could be other 'User's key changed' events then for the
                    # anonymized user.
                    if entry['objectItem']['name'] != lower_case_user_name:
                        continue

                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())
                    anonymized_data['user_key'] = entry['objectItem']['id']
                    user.anonymized_user_key = entry['objectItem']['id']

                #
                # Get the anonymized user-display-name.
                #
                # Until at least Jira 8.9 the "summary" is always EN and is "User updated". An
                # entry looks like:
                #
                #         {
                #             "id": 10645,
                #             "summary": "User updated",
                #             "authorKey": "admin",
                #             "created": "2021-10-02T19:05:17.751+0000",
                #             "category": "Benutzerverwaltung",
                #             "eventSource": "",
                #             "objectItem": {
                #                 "id": "user1pre84",
                #                 "name": "User1Pre84",
                #                 "typeName": "USER",
                #                 "parentId": "1",
                #                 "parentName": "Jira Internal Directory"
                #             },
                #             "changedValues": [
                #                 {
                #                     "fieldName": "Full name",
                #                     "changedFrom": "User 1 Pre 84",
                #                     "changedTo": "user-57690"
                #                 },
                #                 {
                #                     "fieldName": "Email",
                #                     "changedFrom": "User1Pre84@example.com",
                #                     "changedTo": "JIRAUSER10103@jira.invalid"
                #                 }
                #             ]
                #         }
                #
                elif entry['summary'] == 'User updated':
                    # There can be other 'User updated' entries then for the anonymized user. This
                    # is the case if some other user e. g. is renamed during anonymization. Check
                    # if this entry is for the anonymized user.
                    if entry['objectItem']['name'] != user.name:
                        continue

                    user.logs['rest_auditing']['pages'].update(auditlog_iterator.get_current_page())

                    for changed_value in entry['changedValues']:
                        if changed_value['fieldName'] == 'Full name':
                            anonymized_data['display_name'] = changed_value['changedTo']
                            user.anonymized_user_display_name = changed_value['changedTo']
                            break

            except KeyError:
                pass

        self.set_original_values_for_non_anonymized_values(user)

    def set_original_values_for_non_anonymized_values(self, user):
        # If there was no entry for name, key, or display name, the item was not changed.
        # Keep the original as anonymized item.
        if not user.anonymized_user_name:
            user.anonymized_user_name = user.name
            self.log.info(f"hasen't found the anonymized user-name for user '{user.name}'"
                          f" in the audit-log. Kept the name '{user.name}' ")
        if not user.anonymized_user_key:
            user.anonymized_user_key = user.key
            # Do not print the following message. Users created in Jira-versions >= 8.4
            # have keys of format JIRAUSER12345, and those keys won't be anonymized.
            # The following message would be printed for all users created >= 8.4.
            # self.log.info(f"hasen't found the anonymized user-key for user '{user.name}'"
            #              f" in the audit-log. Kept the key '{user.key}' ")
        if not user.anonymized_user_display_name:
            user.anonymized_user_display_name = user.display_name
            self.log.info(f"hasen't found the anonymized user-display-name for user '{user.name}'"
                          f" in the audit-log. Kept the display-name '{user.display_name}' ")

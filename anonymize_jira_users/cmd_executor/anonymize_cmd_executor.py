import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from auditlog_reader import AuditlogReader
from cmd_executor.validate_cmd_executor import ValidateCmdExecutor
from jira import Jira
from jira_user import JiraUser
from report_generator import ReportGenerator
from tools import Tools


@dataclass
class AnonymizeCmdExecutor(ValidateCmdExecutor):
    new_owner: JiraUser = field(init=False)

    def __post_init__(self):
        super().__post_init__()
        self.jira = Jira(config=self.config, log=self.log, execution_logger=self.execution_logger,
                         exiting_error_handler=self.exiting_error_handler)
        self.auditlog_reader = AuditlogReader(config=self.config, log=self.log, jira=self.jira,
                                              execution_logger=self.execution_logger)

    # Override
    def check_cmd_parameters(self):
        super().check_cmd_parameters()

        new_owner_name = self.config.effective_config.get('new_owner')
        if not new_owner_name:
            self.exiting_error_handler("Missing parameter 'new_owner'.")

        self.log.debug(f": Checking if new_owner '{new_owner_name}' is existant and active:")
        r = self.jira.get_user_data(user_name=new_owner_name, is_include_deleted=True)
        r_serialized = Jira.serialize_response(r)
        self.execution_logger.logs['rest_get_user__new_owner'] = r_serialized
        self.log.debug(f"for new_owner '{new_owner_name}' returned {r_serialized}")

        if r.status_code != 200:
            if r.status_code == 404:
                self.exiting_error_handler(r.json()['errorMessages'])
            else:
                r.raise_for_status()

        self.new_owner = JiraUser.from_json(r.json())

        if self.new_owner.deleted:
            self.exiting_error_handler(
                f"The new_owner '{new_owner_name}' is a deleted user. Expect an existant user.")
        if not self.new_owner.active:
            self.exiting_error_handler(
                f"The new_owner '{new_owner_name}' is an inactive user. Expect an active user.")

    # Override
    def execute(self):
        super().execute()

        if self.jira.is_any_anonymization_running():
            self.log.error("There is an anonymization running, or the status of anonymization"
                           " couldn't be read. In both cases this script aborts because these"
                           " cases are not handled. Exiting.")
            sys.exit(2)

        self.anonymize_users()

        if self.config.effective_config['is_trigger_background_reindex']:
            is_any_user_anonymized = any((ReportGenerator.is_user_anonymized(user) for user in self.users))
            if is_any_user_anonymized:
                # Let the user know if a re-index has been triggered.
                # The following attribute 'is_background_reindex_triggered' is not the parameter
                # 'is_trigger_background_reindex' got from the command-line.
                # The Anonymizer uses two different parameters because a re-index is only triggered
                # if at least one user has been anonymized.
                self.jira.trigger_reindex()
                self.execution_logger.logs['is_background_reindex_triggered'] = True

    def wait_until_anonymization_is_finished_or_timedout(self, user_num: int, user: JiraUser):
        """Wait until the anonymization for the given user has been finished.
        :return: False if anonymization finished within the timeout. True otherwise (= timed out).
        """
        self.log.debug(f"for user #{user_num} '{user.name}'")
        rel_progress_url = user.logs['rest_post_anonymization']['json']['progressUrl']
        is_timed_out = True
        started_at = datetime.now()
        timeout = self.config.effective_config['timeout']
        times_out_at = started_at + timedelta(seconds=timeout) if timeout else None
        # Print progress once a minute.
        next_progress_print_at = started_at + timedelta(minutes=1)
        while times_out_at is None or datetime.now() < times_out_at:
            progress_percentage = self.jira.get_anonymization_progress(user, rel_progress_url)
            # Any value <0 means "not in progress".
            if progress_percentage < 0:
                is_timed_out = False
                break
            if datetime.now() >= next_progress_print_at:
                self.log.info(f"Progress {progress_percentage}%")
                next_progress_print_at += timedelta(minutes=1)
            time.sleep(self.config.effective_config['regular_delay'])

        return is_timed_out

    def anonymize_users(self):
        self.log.info(f"starting anonymizing {len(self.remaining_users)} users:")
        for user_num, user in enumerate(self.remaining_users, start=1):
            self.anonymize_user(user_num, user)

    def anonymize_user(self, user_num, user: JiraUser):
        self.log.info(f"#{user_num} (name/key): {user.name}/{user.key}")
        r = self.jira.anonymize_user(user.key, self.new_owner.key)
        user.logs['rest_post_anonymization'] = Jira.serialize_response(r)
        self.log.debug(f"for '{user.name}' returned {user.logs['rest_post_anonymization']}")
        if r.status_code == 202:
            self.log.debug(f": Waiting the initial delay of {self.config.effective_config['initial_delay']}s.")
            time.sleep(self.config.effective_config['initial_delay'])
            is_timed_out = self.wait_until_anonymization_is_finished_or_timedout(user_num, user)

            try:
                # startTime should always be present.
                time_start = user.logs['rest_get_anonymization_progress']['json']['startTime']
                user.time_start = time_start
                # In case the anonymization has been aborted, finishTime could be absent.
                # In this case, a KeyError is raised, and no diff is calculated.
                time_finish = user.logs['rest_get_anonymization_progress']['json']['finishTime']
                user.time_finish = time_finish
                diff = Tools.time_diff(user.time_start, user.time_finish)
                user.time_duration = Tools.get_formatted_timediff_mmss(diff)
            except KeyError:
                pass

            # Collecting the anonymized user-data is done before handling the timeout to
            # save what still can be saved.
            self.auditlog_reader.get_anonymized_user_data_from_audit_log(user)
            # TODO check for completeness. This is at least the anonymized user-name and user-key. If the user
            # was not deleted, this is also the user-display-name.
            if is_timed_out:
                error_message = f"Anonymizing of user '{user.name}' took longer than the" \
                                f" configured timeout of {self.config.effective_config['timeout']}" \
                                " seconds. Aborting."
                self.execution_logger.logs['errors'].append(error_message)
                self.log.error(error_message)
                return
            user.action = 'anonymized'
        else:
            # These error-status-codes are documented:
            #  - 400 Returned if a mandatory parameter was not provided.
            #  - 403 Returned if the logged-in user cannot anonymize users.
            #  - 409 Returned if another user anonymization process is already in progress.
            if r.status_code == 400 or r.status_code == 403 or r.status_code == 409:
                self.log.error(
                    f": A problem occurred scheduling anonymization for user {user.name}."
                    f" See report {self.config.effective_config['report_details_filename']}"
                    " for details.")
            else:
                # For all other, not documented HTTP-problems:
                r.raise_for_status()

    # Overview
    def post_execute(self):
        num_users = len(self.users)
        num_skipped_users = len([user for user in self.users if user.action == 'skipped'])
        num_anonymized_users = len([user for user in self.users if user.action == 'anonymized'])
        overview_data = [
            {
                'name': 'Users in user-list-file',
                'key': 'number_of_users_in_user_list_file',
                'value': num_users
            },
            {
                'name': 'Skipped users',
                'key': 'number_of_skipped_users',
                'value': num_skipped_users
            },
            {
                'name': 'Anonymized user',
                'key': 'number_of_anonymized_users',
                'value': num_anonymized_users
            },
            {
                'name': 'Background re-index triggered',
                'key': 'is_background_reindex_triggered',
                'value': self.execution_logger.logs.get('is_background_reindex_triggered', False)
            }
        ]
        self.report_generator.write_anonymization_report(overview_data)
        self.report_generator.print_overview(overview_data)

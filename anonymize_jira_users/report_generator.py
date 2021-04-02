import csv
import json
from dataclasses import dataclass, field, asdict
from typing import List

from config import Config
from execution_logger import ExecutionLogger
from jira_user import JiraUser
from tools import Tools


@dataclass
class ReportGenerator:
    config: Config
    execution_logger: ExecutionLogger
    users: List[JiraUser] = field(init=False)

    def __post_init__(self):
        self.log = self.config.log

    @staticmethod
    def is_user_anonymized(user: JiraUser):
        return user.logs['rest_get_anonymization_progress']['status_code'] == 200 and \
               user.logs['rest_get_anonymization_progress']['json']['status'] == 'COMPLETED'

    def set_script_finished_date_and_execution_time(self):
        if 'script_finished' not in self.execution_logger.logs:
            self.execution_logger.logs['script_finished'] = Tools.now_to_date_string()
            self.execution_logger.logs['is_script_aborted'] = True
            self.log.warning("Script has been aborted.")

        self.execution_logger.logs['script_execution_time'] = \
            Tools.get_formatted_timediff_hhmmss(
                # time_diff() expects a format with milliseconds
                Tools.time_diff(
                    self.execution_logger.logs['script_started'] + '.000',
                    self.execution_logger.logs['script_finished'] + '.000'))

    def write_details_report(self):
        self.set_script_finished_date_and_execution_time()

        report_dirpath = self.config.create_report_dir()
        file_path = report_dirpath.joinpath(self.config.effective_config['report_details_filename'])
        self.log.debug(f"to {file_path}")
        with open(file_path, 'w') as f:
            report_details_data = {
                'effective_config': self.config.sanitized_effective_config,
                'execution_logger': asdict(self.execution_logger),
                'users': [user.asdict_for_report() for user in self.users]
            }
            # ensure_ascii=False: Write as chars, not as codes. With True, dump() would output
            # something like \u00c3 in case of a non-ASCII char.
            print(json.dumps(report_details_data, indent=4, ensure_ascii=False), file=f)

    def write_anonymization_report(self):
        self.set_script_finished_date_and_execution_time()

        report_dirpath = self.config.create_report_dir()
        file_path = report_dirpath.joinpath(self.config.effective_config['report_json_filename'])
        self.log.debug(f"as JSON to {file_path}")

        raw_report = self.create_raw_report()

        with open(file_path, 'w') as f:
            # ensure_ascii=False: Write as chars, not as codes. With True, dump() would output
            # something like \u00c3 in case of a non-ASCII char.
            print(json.dumps(raw_report, indent=4, ensure_ascii=False), file=f)

        file_path = report_dirpath.joinpath(self.config.effective_config['report_text_filename'])
        self.log.debug(f"as CSV to {file_path}")
        with open(file_path, 'w', newline='') as f:
            fieldnames = ['name', 'key', 'display_name', 'active', 'deleted',
                          'validation_has_errors',
                          'filter_is_anonymize_approval', 'filter_error_message',
                          'action',
                          'time_start', 'time_finish', 'time_duration',
                          'anonymized_user_name', 'anonymized_user_key', 'anonymized_user_display_name']

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(raw_report['users'])

        self.write_result_to_console(raw_report['overview'])

    def create_raw_report(self):
        try:
            is_background_reindex_triggered = self.execution_logger.logs['is_background_reindex_triggered']
        except KeyError:
            is_background_reindex_triggered = False

        report = {
            'overview': {
                'number_of_users_in_user_list_file': len(self.users),
                'number_of_skipped_users': len([user for user in self.users if user.action == 'skipped']),
                'number_of_anonymized_users': len([user for user in self.users if user.action == 'anonymized']),
                'is_background_reindex_triggered': is_background_reindex_triggered
            },
            'users': [user.asdict_for_report() for user in self.users]
        }

        return report

    def write_result_to_console(self, overview):
        print("Anonymizing Result:")
        print(f"  Users in user-list-file:  {overview['number_of_users_in_user_list_file']}")
        print(f"  Skipped users:            {overview['number_of_skipped_users']}")
        print(f"  Anonymized users:         {overview['number_of_anonymized_users']}")
        print(f"  Background re-index triggered:  {overview['is_background_reindex_triggered']}")
        print("")

        if self.execution_logger.errors:
            print(f"Errors have occurred during execution:\n  {'; '.join(self.execution_logger.errors)}\n")

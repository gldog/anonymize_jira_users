import json
import pathlib
from dataclasses import dataclass

from cmd_executor.anonymize_cmd_executor import AnonymizeCmdExecutor
from cmd_executor.base_cmd_executor import BaseCmdExecutor
from cmd_executor.validate_cmd_executor import ValidateCmdExecutor
from execution_logger import ExecutionLogger
from jira_user import JiraUser
from report_generator import ReportGenerator


@dataclass
class RecreateReportCmdExecutor(BaseCmdExecutor):
    execution_logger: ExecutionLogger

    def __post_init__(self):
        super().__post_init__()

    # Override
    def check_cmd_parameters(self):
        if not self.config.args.report_details_json:
            self.exiting_error_handler(f"Command '{self.config.RECREATE_REPORT_CMD}' needs '-i'")
        if not pathlib.Path(self.config.args.report_details_json).is_file():
            self.exiting_error_handler(f"File '{self.config.effective_config['report_details_json']}' not found")
        if not self.config.args.report_out_dir:
            self.exiting_error_handler(f"Command '{self.config.RECREATE_REPORT_CMD}' needs '-o'")
        if pathlib.Path(self.config.args.report_out_dir).exists():
            self.exiting_error_handler(f"Path '{self.config.args.report_out_dir}' already exists")

    # Override
    def execute(self):

        with open(self.config.args.report_details_json, 'r') as f:
            report_details_json = json.load(f)

        command_phrase = f"effective_config.subparser_name in {self.config.args.report_details_json}"
        try:
            command = report_details_json['effective_config']['subparser_name']
            self.log.debug(f"has found command '{command}' from {command_phrase}")
        except KeyError:
            raise ValueError("No value for effective_config.subparser_name found in"
                             f" {self.config.args.report_details_json}")

        if command in [self.config.VALIDATE_CMD, self.config.ANONYMIZE_CMD]:
            report_generator = ReportGenerator(config=self.config, execution_logger=self.execution_logger)

            for user_json in report_details_json['users']:
                report_generator.users.append(JiraUser(user_json=user_json))

            if command == self.config.VALIDATE_CMD:
                report_generator.overview_data = ValidateCmdExecutor.get_overview_data(
                    num_users=len(report_generator.users),
                    num_skipped_users=ValidateCmdExecutor.get_num_skipped_users(report_generator.users))
                report_generator.write_report()
            else:
                # In early versions of the Anonymizer only the fact of is_background_reindex_triggered = True was
                # written to the report_details.json. In case no reindex was triggered, this values wasn't set.
                try:
                    is_background_reindex_triggered = \
                        report_details_json['execution_logger']['is_background_reindex_triggered']
                except KeyError:
                    is_background_reindex_triggered = False

                report_generator.overview_data = AnonymizeCmdExecutor.get_overview_data(
                    num_users=len(report_generator.users),
                    num_skipped_users=AnonymizeCmdExecutor.get_num_skipped_users(report_generator.users),
                    num_anonymized_users=AnonymizeCmdExecutor.get_num_anonymized_users(report_generator.users),
                    is_background_reindex_triggered=is_background_reindex_triggered)
                report_generator.write_report()
        else:
            self.log.warning(
                f"Found command {command}, but expect '{self.config.VALIDATE_CMD}' or '{self.config.ANONYMIZE_CMD}'"
                f" in {command_phrase}. No re-creation has been done.")

from dataclasses import dataclass
from typing import List

from cmd_executor.iva_base_cmd_executor import IVABaseCmdExecutor
from config import Config
from jira import Jira
from tools import Tools


@dataclass
class InactiveUsersCmdExecutor(IVABaseCmdExecutor):
    config: Config
    exclude_groups: List[str] = None

    def __post_init__(self):
        super().__post_init__()
        self.jira = Jira(config=self.config, log=self.log, execution_logger=self.execution_logger,
                         exiting_error_handler=self.exiting_error_handler)

    # Override
    def check_cmd_parameters(self):
        super().check_cmd_parameters()

        self.exclude_groups = self.config.effective_config.get('exclude_groups')
        if self.exclude_groups:
            errors = self.jira.check_if_groups_exist(self.exclude_groups)
            if errors:
                self.exiting_error_handler(', '.join(errors))

    # Override
    def execute(self):

        excluded_users = []
        if self.exclude_groups:
            excluded_users = self.jira.get_users_from_groups(self.exclude_groups)
            self.execution_logger.logs['excluded_users'] = excluded_users

        remaining_inactive_users = self.jira.get_inactive_users(excluded_users)
        self.execution_logger.logs['remaining_inactive_users'] = remaining_inactive_users

        report_dirpath = self.config.create_report_dir()
        file_path = report_dirpath.joinpath(self.config.INACTIVE_USERS_OUTFILE)
        with open(file_path, 'w') as f:
            print(f"# File {self.config.INACTIVE_USERS_OUTFILE} generated at {Tools.now_to_date_string()}\n", file=f)
            print(f"# Users: {len(remaining_inactive_users)}\n", file=f)
            print("# User attributes: User-name; user-key; display-name; email-address\n", file=f)
            for user in remaining_inactive_users:
                print(f"# {user.name}; {user.key}; {user.display_name}; {user.email_address}", file=f)
                print(f"{user.name}\n", file=f)

        self.log.info(f"wrote file {file_path} with {len(remaining_inactive_users)} users.")

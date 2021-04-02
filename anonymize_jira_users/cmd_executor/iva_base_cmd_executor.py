import abc
import atexit
import json
import sys
from dataclasses import dataclass
from typing import List

from cmd_executor.base_cmd_executor import BaseCmdExecutor
from execution_logger import ExecutionLogger
from jira import Jira
from jira_user import JiraUser
from report_generator import ReportGenerator


@dataclass
class IVABaseCmdExecutor(BaseCmdExecutor):
    """Base-class for InactiveUsersCmdExecutor, ValidateCmdExecutor, and AnonymizeCmdExecutor."""

    execution_logger: ExecutionLogger

    def __post_init__(self):
        super().__post_init__()

        if self.config.args.info:
            print(f"Effective config:\n{json.dumps(self.config.sanitized_effective_config, indent=4)}")
            print("")
            sys.exit(0)

        self.report_generator = ReportGenerator(config=self.config, execution_logger=self.execution_logger)
        self.jira = Jira(config=self.config, log=self.log, execution_logger=self.execution_logger)
        self.users: List[JiraUser] = []
        self.report_generator.users = self.users

    # @abc.abstractmethod
    def check_cmd_parameters(self):
        atexit.register(self.report_generator.write_details_report)
        self.log.debug(f"Effective config: {self.config.sanitized_effective_config}")

    @abc.abstractmethod
    def execute(self):
        pass

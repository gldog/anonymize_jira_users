from dataclasses import dataclass

from cmd_executor.anonymize_cmd_executor import AnonymizeCmdExecutor
from cmd_executor.inactive_users_cmd_executor import InactiveUsersCmdExecutor
from cmd_executor.validate_cmd_executor import ValidateCmdExecutor
from cmd_executor.write_config_template_cmd_executor import WriteConfigTemplateCmdExecutor
from config import Config
from execution_logger import ExecutionLogger


@dataclass
class CmdExecutorFactory:
    config: Config
    execution_logger: ExecutionLogger

    def new_instance(self):
        if self.config.args.subparser_name == self.config.WRITE_CONFIG_TEMPLATE_CMD:
            return WriteConfigTemplateCmdExecutor(self.config,
                                                  log=self.config.log,
                                                  exiting_error_handler=self.config.write_config_template_subparser.error)
        elif self.config.args.subparser_name in [self.config.INACTIVE_USERS_CMD,
                                                 self.config.VALIDATE_CMD,
                                                 self.config.ANONYMIZE_CMD]:
            log = self.config.log
            if self.config.args.subparser_name == self.config.INACTIVE_USERS_CMD:
                return InactiveUsersCmdExecutor(config=self.config,
                                                log=log,
                                                execution_logger=self.execution_logger,
                                                exiting_error_handler=self.config.inactive_users_subparser.error)
            elif self.config.args.subparser_name == self.config.VALIDATE_CMD:
                return ValidateCmdExecutor(config=self.config,
                                           log=log,
                                           execution_logger=self.execution_logger,
                                           exiting_error_handler=self.config.validate_supparser.error)
            elif self.config.args.subparser_name == self.config.ANONYMIZE_CMD:
                return AnonymizeCmdExecutor(config=self.config,
                                            log=log,
                                            execution_logger=self.execution_logger,
                                            exiting_error_handler=self.config.anonymize_subparser.error)
        else:
            return None

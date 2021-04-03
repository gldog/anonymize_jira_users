import sys

from cmd_executor.base_cmd_executor import BaseCmdExecutor
from config import Config


class MiscCmdExecutor(BaseCmdExecutor):
    config: Config

    def __post_init__(self):
        super().__post_init__()

    # Override
    def check_cmd_parameters(self):
        if not self.config.args.config_template_filename:
            # error_handler() exits.
            self.error_handler(f"Command '{self.config.MISC_CMD}' needs '-g'")

    # Override
    def execute(self):
        self.config.write_config_template_file()
        self.log.info(f"Wrote {self.config.args.config_template_filename}")
        sys.exit(0)

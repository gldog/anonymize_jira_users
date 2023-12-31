from cmd_executor.cmd_executor_factory import CmdExecutorFactory
from config import Config
from execution_logger import ExecutionLogger
from tools import Tools

execution_logger = ExecutionLogger()
execution_logger.logs['script_started'] = Tools.now_to_date_string()

# Config also creates and sets up the Logger.
config = Config()

cmd_executor = CmdExecutorFactory(config=config, execution_logger=execution_logger).new_instance()
cmd_executor.check_cmd_parameters()
cmd_executor.execute()

execution_logger.logs['is_script_aborted'] = False
execution_logger.logs['script_finished'] = Tools.now_to_date_string()

# Note, there is also the post_execute(). It is registered for atexit if needed

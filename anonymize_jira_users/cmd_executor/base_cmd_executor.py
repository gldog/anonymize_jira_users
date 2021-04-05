import abc
from argparse import ArgumentParser
from dataclasses import dataclass
from logging import Logger

from config import Config


@dataclass
class BaseCmdExecutor(metaclass=abc.ABCMeta):
    config: Config
    log: Logger
    exiting_error_handler: ArgumentParser.error

    def __post_init__(self):
        pass

    @abc.abstractmethod
    def check_cmd_parameters(self):
        pass

    @abc.abstractmethod
    def execute(self):
        pass

    def post_execute(self):
        pass

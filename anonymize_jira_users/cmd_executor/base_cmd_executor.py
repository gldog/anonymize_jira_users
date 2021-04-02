import abc
from dataclasses import dataclass
from logging import Logger

from config import Config


@dataclass
class BaseCmdExecutor(metaclass=abc.ABCMeta):
    config: Config
    log: Logger

    def __post_init__(self):
        pass

    @abc.abstractmethod
    def check_cmd_parameters(self):
        pass

    @abc.abstractmethod
    def execute(self):
        pass

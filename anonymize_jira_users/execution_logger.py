from dataclasses import dataclass, field


@dataclass
class ExecutionLogger:
    errors: list = field(default_factory=list, init=False)
    logs: dict = field(default_factory=dict, init=False)

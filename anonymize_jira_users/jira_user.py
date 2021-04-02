from dataclasses import dataclass, field


@dataclass
class JiraUser:
    name: str = field(default=None)
    key: str = field(default=None)
    display_name: str = field(default=None)
    email_address: str = field(default=None)
    active: bool = field(default=None)
    # deleted: Since Jira 8.10.
    deleted: bool = field(default=None)
    validation_has_errors: bool = field(default=None)
    filter_is_anonymize_approval: bool = field(default=None)
    filter_error_message: str = field(default=None)
    time_start: str = field(default=None)
    time_finish: str = field(default=None)
    time_duration: str = field(default=None)
    anonymized_user_name: str = field(default='')
    anonymized_user_key: str = field(default='')
    anonymized_user_display_name: str = field(default='')
    action: str = field(default=None)
    logs: dict = field(default_factory=dict)

    def set_from_json(self, user_json):
        user = self.from_json(user_json)
        self.name = user.name
        self.key = user.key
        self.display_name = user.display_name
        self.email_address = user.email_address
        self.active = user.active
        self.deleted = user.deleted

    @staticmethod
    def from_json(user_json):
        user = JiraUser()
        # These four could throw KeyError. But it is expected once given the proper
        # REST-response-JSON, all four attributes are present.
        # The user-name is allowed to consist of only digits, but it must be interpreted as string.
        user.name = str(user_json['name'])
        # Same for the key for users created in Jira <8.4.
        user.key = str(user_json['key'])
        user.display_name = str(user_json['displayName'])
        user.email_address = user_json['emailAddress']
        user.active = user_json['active']
        # 'deleted' Since Jira 8.10.
        user.deleted = user_json['deleted'] if 'deleted' in user_json else None

        return user

    def asdict_for_detailed_report(self):
        """Return a dict comprising of almost all properties, but not 'from_json'."""
        return {k: v for k, v in self.__dict__.items() if k not in ['from_json']}

    def asdict_for_report(self):
        """
        Return a dict comprising of almost all properties, but not 'from_json', 'logs',
        'email_address'.
        """
        return {k: v for k, v in self.__dict__.items() if k not in ['from_json', 'logs', 'email_address']}

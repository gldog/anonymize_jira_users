from dataclasses import dataclass, field


@dataclass
class JiraUser:
    user_json: dict = field(default=None)
    name: str = field(default=None)
    key: str = field(default=None)
    display_name: str = field(default=None)
    email_address: str = field(default=None)
    active: bool = field(default=None)
    # deleted: Since Jira 8.10.
    # The value is None in Jira versions before 8.10. Since 8.10, the value is False for existing
    # users and True for deleted users.
    deleted: bool = field(default=None)
    filter_error_message: str = field(default=None)
    anonymization_start_time: str = field(default=None)
    anonymization_finish_time: str = field(default=None)
    anonymization_duration: str = field(default=None)
    anonymized_user_name: str = field(default='')
    anonymized_user_key: str = field(default='')
    anonymized_user_display_name: str = field(default='')
    action: str = field(default=None)
    logs: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.user_json:
            # The user-name is allowed to consist of only digits, but it must be interpreted as string.
            self.name = self.strvalue_or_none(self.user_json['name'])
            # Same for the key for users created in Jira <8.4.
            self.key = self.strvalue_or_none(self.user_json['key'])
            # 'displayName' is the attribute in the REST response, and 'display_name' the one in
            # the report_details.json.
            self.display_name = self.find_first_attr(self.user_json, ['displayName', 'display_name'])
            # 'emailAddress' is the attribute in the REST response, and 'email_address' the one in
            # the report_details.json.
            self.email_address = self.find_first_attr(self.user_json, ['emailAddress', 'email_address'], '')
            self.active = self.user_json['active']
            # 'deleted' Since Jira 8.10.
            self.deleted = self.user_json.get('deleted')
            self.filter_error_message = self.user_json.get('filter_error_message', '')
            self.anonymization_start_time = self.user_json.get('anonymization_start_time', '')
            self.anonymization_finish_time = self.user_json.get('anonymization_finish_time', '')
            self.anonymization_duration = self.user_json.get('anonymization_duration', '')
            self.anonymized_user_name = self.user_json.get('anonymized_user_name', '')
            self.anonymized_user_key = self.user_json.get('anonymized_user_key', '')
            self.anonymized_user_display_name = self.user_json.get('anonymized_user_display_name', '')
            self.action = self.user_json.get('action', '')

    @staticmethod
    def strvalue_or_none(val):
        return str(val) if val is not None else None

    @staticmethod
    def find_first_attr(user_json, attr_list, default=None):
        for attr in attr_list:
            try:
                v = user_json[attr]
                return str(v) if v is not None else None
            except KeyError:
                pass
        return default

    def recreate_from_json(self, user_json):
        user = self.from_json(user_json)
        self.name = user.name
        self.key = user.key
        self.display_name = user.display_name
        self.email_address = user.email_address
        self.active = user.active
        self.deleted = user.deleted

    @staticmethod
    def from_json(user_json: dict):
        user = JiraUser()
        # The user-name is allowed to consist of only digits, but it must be interpreted as string.
        user.name = str(user_json['name'])
        # Same for the key for users created in Jira <8.4.
        user.key = str(user_json['key'])
        user.display_name = str(user_json['displayName'])
        user.email_address = user_json['emailAddress']
        user.active = user_json['active']
        # 'deleted' Since Jira 8.10.
        user.deleted = user_json.get('deleted')

        return user

    def asdict_for_detailed_report(self):
        """Return a dict comprising of almost all properties, but not 'from_json'."""
        return {k: v for k, v in self.__dict__.items()}

    def asdict_for_report(self):
        """
        Return a dict comprising of almost all properties, but not 'from_json', 'logs',
        'email_address'.
        """
        return self.filter_dict_for_report(self.__dict__)

    @staticmethod
    def filter_dict_for_report(user_json):
        return {k: v for k, v in user_json.items() if k not in ['user_json', 'logs', 'email_address']}

    def is_anonymized_data_complete(self):
        """Check if all three anonymized items user-name, -key, and display-name are given.
         If so, this user is anonymized.

         In Jira versions before 8.10 all values except the .name are None for deleted users. In
         Jira versions starting with 8.10 the .deleted is either False for an existing user or
         True for a deleted user. Deleted users doesn't have a display-name and won't have an
         anonymized display-name.
         Since Jira 8.10, the data of deleted users still exist and have a name and a key, but no
         display-name.
         """

        #   >= 8.10 |   is user     |   attr.   |   attr.   ||  rule for is_complete
        #           |   deleted?    |   deleted |   key     ||
        #       N           N           None        <key>       name & key & display_name
        #       N           Y           None        None        True
        #       Y           N           False       <key>       name & key & display_name
        #       Y           Y           True        <key>       name & key & True
        is_complete = self.key is None \
                      or \
                      self.anonymized_user_name and self.anonymized_user_key \
                      and (True if self.deleted else self.anonymized_user_display_name)
        return is_complete

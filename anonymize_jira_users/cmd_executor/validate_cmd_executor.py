import atexit
import re
from dataclasses import dataclass
from os import access, R_OK
from os.path import isfile

from cmd_executor.iva_base_cmd_executor import IVABaseCmdExecutor
from jira import Jira
from jira_user import JiraUser


@dataclass
class ValidateCmdExecutor(IVABaseCmdExecutor):
    remaining_users = []

    def __post_init__(self):
        super().__post_init__()
        self.jira = Jira(config=self.config, log=self.log, execution_logger=self.execution_logger,
                         exiting_error_handler=self.exiting_error_handler)

    # Override
    def check_cmd_parameters(self):
        super().check_cmd_parameters()
        # Check if user_list_file is given in config and is readable.
        errors = []
        user_list_file = self.config.effective_config.get('user_list_file')
        if not user_list_file:
            errors.append("Missing parameter 'user_list_file'")
        else:
            if not (isfile(user_list_file) and access(user_list_file, R_OK)):
                self.exiting_error_handler(
                    f"User_list_file {self.config.effective_config['user_list_file']}"
                    " does not exist or is not accessible")

    # Override
    def execute(self):
        atexit.register(self.report_generator.write_anonymization_report)

        self.read_users_from_user_list_file()
        self.get_user_data()
        self.filter_by_existance()
        self.filter_by_active_status()
        self.get_anonymization_validation_data()
        self.filter_by_validation_errors()

    def read_users_from_user_list_file(self):
        """Read the Jira user-names from the user-names-file. Skip lines starting with hash '#'.

        :return: None.
        """
        self.log.info(self.config.effective_config["user_list_file"])
        with open(self.config.effective_config["user_list_file"], 'r',
                  encoding=self.config.effective_config['encoding']) as f:
            user_list_file = f.read()
            lines = re.split('[\n\r]+', user_list_file)
            for line in lines:
                line = line.strip()
                # Skip comment lines.
                if line and not line.startswith('#'):
                    user_name = line
                    self.users.append(JiraUser(name=user_name))

        self.log.info(f"found ({len(self.users)}) users: {[user.name for user in self.users]}")
        self.remaining_users = self.users.copy()

    def get_user_data(self):
        """Get each user's data before anonymization."""

        self.log.info(f"for {len(self.users)} users")
        for user in self.users:
            self.log.debug(f"for '{user.name}'")
            r = self.jira.get_user_data(user_name=user.name, is_include_deleted=True)
            r_serialized = Jira.serialize_response(r, True)
            self.log.debug(f"for '{user.name}' returned {r_serialized}")
            user.logs['rest_get_user__before_anonymization'] = r_serialized
            if user.logs['rest_get_user__before_anonymization']['status_code'] == 200:
                user.recreate_from_json(r_serialized['json'])
            else:
                # This is the case for not-existing users:
                errors = r_serialized['json'].get('errorMessages')
                if errors:
                    self.log.debug(f"for '{user.name}' returned the error {errors}")
                # Don't know if this could happen, but technically the 'error' is in the response.
                errors = r_serialized['json'].get('errors')
                if errors:
                    self.log.debug(f"for '{user.name}' returned the error {errors}")

    def filter_by_existance(self):
        self.log.info(f"{len(self.remaining_users)} users")
        remaining_users = []
        for user in self.remaining_users:
            json_ = user.logs['rest_get_user__before_anonymization']
            if json_['status_code'] == 200:
                self.log.debug(f"'{user.name}': Keep")
                remaining_users.append(user)
            else:
                # Default in case no error moessage is given.
                user.filter_error_message = 'Not existing'
                # errorMessages is given in case of not-existing users:
                errors = json_['json'].get('errorMessages')
                if errors:
                    user.filter_error_message = ', '.join(errors)
                    self.log.debug(f"for '{user.name}' returned the error {errors}")
                self.log.info(f"'{user.name}': Skip. {user.filter_error_message}")

        self.remaining_users = remaining_users

    def filter_by_active_status(self):
        self.log.info(f"{len(self.remaining_users)} users:")
        remaining_users = []
        for user in self.remaining_users:
            # 'asctive' can be None, False, or True. Non is the default nor not yet initialized
            # users. Because not existing users are filtered out in the previous filter, all
            # remaining users are existing ones and must have an 'active' of either False or True.
            if not user.active:
                self.log.debug(f"'{user.name}': Keep")
                remaining_users.append(user)
            else:
                error_msg = "Is an active user."
                user.filter_error_message = error_msg
                self.log.info(f"'{user.name}': Skip. {error_msg}")

        self.remaining_users = remaining_users

    def get_anonymization_validation_data(self):
        if len(self.users) == len(self.remaining_users):
            self.log.info(f"for {len(self.remaining_users)} users:")
        else:
            self.log.info(f"for {len(self.remaining_users)} of {len(self.users)} users")

        for user in self.remaining_users:
            self.log.info(f"for '{user.name}'")
            r = self.jira.get_anonymization_validation_data(user)
            r_serialized = Jira.serialize_response(r)
            user.logs['rest_get_anonymization__query_validation'] = r_serialized
            self.log.debug(f"for '{user.name}' returned {r_serialized}")

            # These status-codes are documented:
            #  - 200 Returned when validation succeeded.
            #  - 400 Returned if a mandatory parameter was not provided or validation failed.
            #  - 403 Returned if the logged-in user cannot anonymize users
            if r.status_code not in [200, 400, 403]:
                # For all other not documented HTTP-problems:
                r.raise_for_status()

    def filter_by_validation_errors(self):
        self.log.info(f"{len(self.remaining_users)} users:")

        remaining_users = []
        for user in self.remaining_users:
            # 0 or 1 error expected per user (not a list of errors).
            error_messages = []

            query_validation = user.logs['rest_get_anonymization__query_validation']
            if query_validation['status_code'] != 200:
                error_messages.append("HTTP status-code of the REST validation API is not 200.")
                # Regardless of the status code there could be validation-errors (seen e.g.
            # in use case "admin tries to anonymize themself": Status code was 400 Bad Request
            # and the error was "You can't anonymize yourself.").
            if query_validation['json']['errors']:
                error_messages.append("There is at least one validation error message.")

            if error_messages:
                user.filter_error_message = '; '.join(error_messages)
                self.log.warning(f"blocks '{user.name}': {error_messages}")
            else:
                user.filter_error_message = ""
                remaining_users.append(user)

        self.remaining_users = remaining_users

        for user in self.users:
            if user not in self.remaining_users:
                user.action = 'skipped'

        self.log.info(f"has approved {len(remaining_users)} of {len(self.users)} users for"
                      f" anonymization: {[user.name for user in remaining_users]}")

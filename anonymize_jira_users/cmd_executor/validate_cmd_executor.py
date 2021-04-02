import atexit
import re
from dataclasses import dataclass

from cmd_executor.iva_base_cmd_executor import IVABaseCmdExecutor
from jira import Jira
from jira_user import JiraUser


@dataclass
class ValidateCmdExecutor(IVABaseCmdExecutor):
    # approved_users: list = field(default_factory=list, init=False)

    def __post_init__(self):
        super().__post_init__()
        pass

    # Override
    def check_cmd_parameters(self):
        super().check_cmd_parameters()
        # Check if user_list_file is missing in config.
        errors = []
        if not self.config.effective_config.get('user_list_file') \
                or not self.config.effective_config.get('user_list_file'):
            errors.append("Missing user_list_file")
        else:
            try:
                open(self.config.effective_config['user_list_file'])
            except IOError:
                errors.append(
                    f"User_list_file {self.config.effective_config['user_list_file']}"
                    " does not exist or is not accessible")
        pass

    # Override
    def execute(self):
        atexit.register(self.report_generator.write_anonymization_report)

        self.read_users_from_user_list_file()
        self.get_user_data()
        self.get_anonymization_validation_data()
        self.filter_users()

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

    def get_user_data(self):
        """Get each user's data before anonymization."""

        self.log.debug(f"for {len(self.users)} users:")
        for user in self.users:
            self.log.info(f"for '{user.name}'")
            r = self.jira.get_user_data(user_name=user.name, is_include_deleted=True)
            r_serialized = Jira.serialize_response(r)
            self.log.debug(f"for '{user.name}' returned {r_serialized}")
            user.logs['rest_get_user__before_anonymization'] = r_serialized
            if user.logs['rest_get_user__before_anonymization']['status_code'] == 200:
                user.reset_from_json(r_serialized['json'])
            else:
                # This is the case for not-existing users:
                json_ = r_serialized['json']
                if 'errorMessages' in json_ and json_['errorMessages']:
                    errors = r_serialized['json']['errorMessages']
                    self.log.warning(f"for '{user.name}' returned the error {errors}")
                # Don't know if this could happen, but technically the 'error' is in the response.
                if 'errors' in json_ and json_['errors']:
                    errors = r_serialized['json']['errors']
                    self.log.warning(f"for '{user.name}' returned the error {errors}")

    def get_anonymization_validation_data(self):
        # TODO The function name get_anonymization_validation_data exists twice. One time here and one time
        # in Jira-class. This will result in logging this name twice.
        # Is logged by Jira-object.

        existing_users = [user for user in self.users if
                          user.logs['rest_get_user__before_anonymization']['status_code'] == 200]
        if len(self.users) == len(existing_users):
            self.log.info(f"for {len(existing_users)} users:")
        else:
            self.log.info(f"for {len(existing_users)} of {len(self.users)} users"
                          f" ({len(self.users) - len(existing_users)} users do not exist):")

        for user in existing_users:
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

    def filter_users(self):
        self.log.info("by existence and anonymizaton-validation-data")

        for user in self.users:
            # 0 or 1 error expected per user (not a list of errors).
            filter_error_message = ""
            user.validation_has_errors = False

            #
            # Give anonymize-approval only to users who are inactive or deleted.
            # A user can be 1. active, 2. inactive, or 3. deleted. So we have to check only if the user
            # is an active users to skip it.
            # A user is active, if GET rest/api/2/user responded with status code 200 OK and the
            # attribute "active" is true.
            #

            # Check if user-data could be retrieved.
            before_anonymization = user.logs['rest_get_user__before_anonymization']
            if before_anonymization['status_code'] != 200:
                filter_error_message = f"{before_anonymization['json']['errorMessages'][0]}"
            else:
                # Check if the user is an active user:
                if user.active:
                    filter_error_message = "Is an active user."

            #
            #  Check against validation result got from GET rest/api/2/user/anonymization.
            #
            if not filter_error_message:
                # try/except: user.logs['rest_get_anonymization__query_validation'] could
                # be absent in case of an invalid user in the user_list_file.
                # TODO ... but in this case there should be a filter error.
                try:
                    query_validation = user.logs['rest_get_anonymization__query_validation']
                    if query_validation['status_code'] != 200:
                        filter_error_message = "HTTP status-code of the REST validation API is not 200."
                    # Regardless of the status code there could be validation-errors (seen e.g.
                    # in use case "admin tries to anonymize themself": Status code was 400 Bad Request
                    # and the error was "You can't anonymize yourself.").
                    if query_validation['json']['errors']:
                        filter_error_message += " There is at least one validation error message."
                        user.validation_has_errors = True
                except KeyError:
                    pass

            user_filter = user.logs['user_filter'] = {}
            user_filter['error_message'] = ""
            if filter_error_message:
                user_filter['error_message'] = filter_error_message
                user_filter['is_anonymize_approval'] = False
                user.filter_error_message = filter_error_message
                user.filter_is_anonymize_approval = False
                self.log.warning(f"blocks '{user.name}': {filter_error_message}")
            else:
                user_filter['is_anonymize_approval'] = True
                user.filter_error_message = ""
                user.filter_is_anonymize_approval = True
                # self.approved_users.append(user)

        approved_users = self.get_approved_users()

        self.log.info(f"has approved {len(approved_users)} of {len(self.users)} users for"
                      f" anonymization: {[user.name for user in approved_users]}")

    def get_approved_users(self):
        return [user for user in self.users if user.filter_is_anonymize_approval]

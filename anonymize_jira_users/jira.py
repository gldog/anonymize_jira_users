import inspect
import re
from argparse import ArgumentParser
from collections import namedtuple
from dataclasses import dataclass
from json import JSONDecodeError
from logging import Logger
from typing import List
from urllib import parse

import requests
import urllib3
from requests import Response

from config import Config
from execution_logger import ExecutionLogger
from jira_user import JiraUser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class HTTPError(Exception):
    pass


@dataclass()
class Jira:
    config: Config
    log: Logger
    execution_logger: ExecutionLogger
    exiting_error_handler: ArgumentParser.error

    SSL_VERIFY = False

    def __post_init__(self):
        self.session = requests.Session()
        self.version_numbers = []

        try:
            if not self.config.effective_config['jira_base_url']:
                raise ValueError("Missing jira_base_url")
            # Set  base-URL, remove trailing slash if present.
            self.base_url = self.config.effective_config['jira_base_url'].rstrip('/')
            if not self.config.effective_config['jira_auth']:
                raise ValueError("Missing authentication")
            auth_type, username_or_bearer_token, password = \
                self.validate_auth_parameter(self.config.effective_config['jira_auth'])
            self.setup_http_session(auth_type, username_or_bearer_token, password)
            self.check_for_admin_permission()
            r = self.get_jira_serverinfo()
            r.raise_for_status()
            self.version_numbers = r.json()['versionNumbers']
            self.execution_logger.logs['rest_get_serverInfo'] = self.serialize_response(r)
        except Exception as e:
            self.exiting_error_handler(e)

    @staticmethod
    def validate_auth_parameter(auth):
        """Check parameter 'auth' for valid auth-type 'Basic' or 'Bearer, extract the auth-data,
        and return them.
        :param auth: Expect either the format 'Basic user:pass', or
                    'Bearer NDcyOTE1ODY4Nzc4Omj+FiGVuLh/vs4WjTS9/3lGaysM'
        :return: AuthValidationResult-tuple.
            1 - The auth-type 'basic' or 'bearer' (lower case).
            2 - In case of 'basic': The user-name. In case of 'bearer': The token.
            3 - In case of 'basic': The password. In case  of 'bearer': None.
        """

        # Split 'Basic' or 'Bearer' from the rest.
        auth_parts = re.split(r'\s+', auth, 1)

        AuthValidationResult = \
            namedtuple('AuthValidationResult', ['auth_type', 'user_name', 'password'])

        if len(auth_parts) < 2:
            raise ValueError(f"{inspect.currentframe().f_code.co_name} detected invalid format in"
                             " authentication parameter.")

        auth_type = auth_parts[0].lower()
        if not auth_type.lower() in ['basic', 'bearer']:
            raise ValueError(f"{inspect.currentframe().f_code.co_name} detected invalid "
                             f"authentication type '{auth_parts[0]}'. Expect 'Basic' or 'Bearer'.")

        username = None
        password = None
        if auth_type == 'basic':
            # The lolon is the delimiter between the username and the password. Split between them.
            # But split only at the first colon, as a colon could be part of the password.
            username_and_password = re.split(r':', auth_parts[1], 1)
            if len(username_and_password) != 2:
                raise ValueError(f"{inspect.currentframe().f_code.co_name} detected invalid format"
                                 " for 'Basic' in authentication argument."
                                 " Expect 'Basic username:password'")
            else:
                username = username_and_password[0]
                password = username_and_password[1]

        bearer_token = None
        if auth_type == 'bearer':
            if len(auth_parts) != 2:
                raise ValueError(f"{inspect.currentframe().f_code.co_name} detected invalid format"
                                 " for 'Bearer' in authentication argument."
                                 " Expect 'Bearer <token>'")
            else:
                bearer_token = auth_parts[1]

        return AuthValidationResult(
            auth_type,
            username if auth_type == 'basic' else bearer_token,
            password if auth_type == 'basic' else None)

    def setup_http_session(self, auth_type, username_or_bearer_token, passwd):
        self.session.verify = self.SSL_VERIFY
        self.session.headers = {
            'Content-Type': 'application/json'
        }
        if auth_type == 'basic':
            self.session.auth = (username_or_bearer_token, passwd)
            url = self.base_url + '/rest/auth/1/session'
            # Expect 200 OK here.
            r = self.session.get(url=url)
            if r.status_code == 401:
                raise HTTPError(f"{inspect.currentframe().f_code.co_name} failed with"
                                f" {r.status_code} due to invalid credentials.")
            if r.status_code == 403:
                raise HTTPError(f"{inspect.currentframe().f_code.co_name} failed with"
                                f" {r.status_code} because the login is denied due to a CAPTCHA"
                                " requirement, throtting, or any other reason."
                                " In case of a 403 status code it is possible that the supplied"
                                " credentials are valid but the user is not allowed to log in at"
                                " this point in time.")
        else:
            self.session.headers = {
                'Authorization': 'Bearer ' + username_or_bearer_token,
                'Content-Type': 'application/json'
            }

    def check_for_admin_permission(self):
        """Check if the user can log-in and is an administrator.

        In Jira there are two levels of administration: The Administrator and the System
        Administrator. The weaker Administrator is sufficient for anonymization. To check against
        administrator-permissions, call the GET /rest/api/2/mypermissions API. This returns among
        others the "ADMINISTR" and the "SYSTEM_ADMIN" entries. Check for
        permissions["ADMINISTER"]["havePermission"]==True. System-admins have both set to true.

        {
            ...,
            "permissions": {
                "ADMINISTER": {
                    "id": "0",
                    "key": "ADMINISTER",
                    "name": "Jira Administrators",
                    "type": "GLOBAL",
                    "description": "Ability to perform most administration functions (excluding
                        >> Import & Export, SMTP Configuration, etc.).",
                    "havePermission": true
                },
                "SYSTEM_ADMIN": {
                    "id": "44",
                    "key": "SYSTEM_ADMIN",
                    "name": "Jira System Administrators",
                    "type": "GLOBAL",
                    "description": "Ability to perform all administration functions. There must be
                        >> at least one group with this permission.",
                    "havePermission": false
                },
            }
        }

        """
        rel_url = '/rest/api/2/mypermissions'
        url = self.base_url + rel_url
        r = self.session.get(url=url)
        self.execution_logger.logs['rest_get_mypermissions'] = self.serialize_response(r, False)
        if r.status_code == 200:
            # Log a reduced JSON, as the whole JSON is very large but most of it is not of interest.
            self.execution_logger.logs['rest_get_mypermissions']['json'] = {}
            self.execution_logger.logs['rest_get_mypermissions']['json']['permissions'] = {}
            self.execution_logger.logs['rest_get_mypermissions']['json']['permissions']['ADMINISTER'] = \
                r.json()['permissions']['ADMINISTER']
            # Now check if the executing user has the appropriate permission.
            if not r.json()['permissions']['ADMINISTER']['havePermission']:
                raise ValueError(f"{inspect.currentframe().f_code.co_name} failed because user is"
                                 " not an administrator. Only roles Administrator and"
                                 " System-Administrator are allowed to anonymize users.")
        else:
            # The documented error-codes are as follows.
            #   - 400 Returned if the project or issue id is invalid.
            #   - 401 Returned request is on behalf of anonymous user and feature flag
            #       `jira.restrict.anonymous.access.to.mypermissions.rest.api.enabled` is enabled
            #   - 404 Returned if the project or issue id or key is not found.
            raise HTTPError(f"{inspect.currentframe().f_code.co_name} failed with {r.status_code}")

    def get_anonymization_progress(self, user: JiraUser = None, rel_progress_url: str = None):
        """Call the Get Progress API and check if there is an anonymization running and to get the
        progress.

        There are two reasons to do this:
            1. Before the first anonymization to check if there is any anonymization running. In
                this case both parameters user_name and full_progress_url must be None / absent.
            2. During the anonymization to check if it is finished. The latest response is stored
                for each user.

        When is an anonymization running, and when it is finished?

        Let's start with the HTTP status codes. 404 means "Returned if there is no user
        anonymization task found.". It is obvious there is no anonymization running. I can return
        something like "No anon. running".

        There is another status code documented: 403 "Returned if the logged-in user cannot
        anonymize users.". This is a problem the script has handled before the anonymization has
        been scheduled and is not checked here (in fact at the end of this function there is a
        r.raise_for_status() as a lifeline in case I haven't implemented a bullet-proof permission
        check earlier).

        There is the HTTP status code 200 left. If that is returned, I have to look into the JSON
        responses "status"-attribute. I haven't a mapping of HTTP status-code to progress
        "status"-attribute yet, by I have the list of "status" values read from the Jira source
        code (jira-project/jira-components/jira-plugins/jira-rest/jira-rest-plugin/src/main/java/
            >> com/atlassian/jira/rest/v2/user/anonymization/UserAnonymizationProgressBean.java):
        These are:
          - COMPLETED The anonymization process finished. Some errors or warnings might be present.
          - INTERRUPTED There is no connection with the node that was executing the anonymization
                process. Usually, this means that the node crashed and the anonymization task needs
                to be cleaned up from the cluster.
          - IN_PROGRESS The anonymization process is still being performed.
          - VALIDATION_FAILED The anonymization process hasn't been started because the validation
                has failed for some anonymization handlers.

        Note, I have seen a "status" "IN_PROGRESS" with a "currentProgress" of 100.

        As a conclusion I can say:

        HTTP status | "status" attribute| An. not running (anymore) | An. is running
                    |                   |   or is finished          |
                    +                   +                           +
            404     |   don't care      |   Yes                     |   No
            200     |   IN_PROGRESS     |   No                      |   Yes
            200     |   other           |   Yes                     |   No

        The "errors" and "warnings" are not evaluated in this implementation step. Maybe later. I
        assume the validation does the job to show errors, and the filter_users() will filter users
        out in case of errors.

        :param user: Optional. Given if there has been scheduled one of our anonymizations. In this
        case, the full_progress_url is also mandatory.
        :param rel_progress_url: Optional. Given if there has been scheduled one of our
        anonymizations. In this case, the user_name is also mandatory.
        :return:
            o The progress (percentage) from the returned JSON. 100 doesn't mean the "status" is
                also "COMPLETED".
            o -1: if HTTP-status is 404 ("Returned if there is no user anonymization task found.").
            o -2: if the "status" is "COMPLETED". I assume a "currentProgress" of 100.
            o -3: Other "status" than "IN_PROGRESS" and "COMPLETED". Means "not in progress".
        """
        self.log.debug(f"for user_name {user.name if user else None}"
                       f" and rel_progress_url {rel_progress_url}")
        assert not (bool(user) ^ bool(rel_progress_url))

        if rel_progress_url:
            url = self.base_url + rel_progress_url
            # Only DEBUG, because this could be called a lot.
            self.log.debug(f"Checking if anonymization for user '{user.name}' is running")
        else:
            rel_url = '/rest/api/2/user/anonymization/progress'
            url = self.base_url + rel_url
            self.log.debug(": Checking if any anonymization is running")
        r = self.session.get(url=url)
        # If this call is for a specific user/anonymization-task, store the response in the user's
        # data.
        r_serialized = self.serialize_response(r)
        if user:
            user.logs['rest_get_anonymization_progress'] = r_serialized
            self.log.debug(f"for '{user.name}': {r_serialized}")
        else:
            self.execution_logger.logs['rest_get_anonymization_progress__before_anonymization'] \
                = r_serialized

        progress_percentage = None
        if r.status_code == 404:
            # "Returned if there is no user anonymization task found."
            progress_percentage = -1
        elif r.status_code == 200:
            if r.json()['status'] == 'IN_PROGRESS':
                # Value between 0 and 100.
                progress_percentage = r.json()['currentProgress']
            elif r.json()['status'] == 'COMPLETED':
                progress_percentage = -2
            else:
                # Other "status" than "IN_PROGRESS" and "COMPLETED". Means "not in progress".
                progress_percentage = -3

        if progress_percentage >= 0:
            self.log.debug(f"for '{user.name}': {progress_percentage}%")
        else:
            d = {-1: 'No user anonymization task found', -2: 'COMPLETED', -3: 'Not in progress'}
            self.log.debug(d[progress_percentage])

        # For any other HTTP status:
        if progress_percentage is None:
            r.raise_for_status()

        return progress_percentage

    def is_any_anonymization_running(self):
        progress_percentage = self.get_anonymization_progress()
        # Any value <0 means "not in progress".
        if progress_percentage < 0:
            self.log.info("? No")
            return False
        else:
            self.log.info("? Yes")
            return True

    @staticmethod
    def serialize_response(r: Response, is_include_json_response=True):
        """Serialize a requests-response to a JSON.

        :param r: The response of a requests.get(), requests.post(), ...
        :param is_include_json_response: True (default), if the response.json() shall be included
            in the serialied  result. With is_include_json_response=False the caller can suppress
            serialization in case of large or uninteresting responses.
        """

        # The body is a b'String in Python3 and is not readable by json.dumps(). It has to be
        # decoded before. The 'utf-8' is only a suggestion here.
        decoded_body = r.request.body.decode('utf-8') if r.request.body else None
        try:
            r_json = r.json()
        except JSONDecodeError:
            r_json = None

        j = {'status_code': r.status_code,
             'requst_body': decoded_body,
             'requst_method': r.request.method,
             'requst_url': r.request.url}

        if is_include_json_response:
            j['json'] = r_json

        return j

    def get_jira_serverinfo(self):
        rel_url = '/rest/api/2/serverInfo'
        url = self.base_url + rel_url
        r = self.session.get(url=url)
        return r

    def is_jira_version_less_then(self, major, minor):
        # versionNumbers is e.g. [8,14,0]
        is_less_then = self.version_numbers[0] < major or (
                self.version_numbers[0] == major and self.version_numbers[1] < minor)
        self.log.debug(f"{major}.{minor}: {is_less_then}")
        return is_less_then

    def get_user_data(self, user_name, is_include_deleted=False):
        rel_url = '/rest/api/2/user'
        self.log.debug(f"for user-name '{user_name}'")
        url = self.base_url + rel_url
        url_params = {'includeDeleted': is_include_deleted, 'username': user_name}
        r = self.session.get(url=url, params=url_params)
        return r

    def check_if_groups_exist(self, group_names):
        rel_url = '/rest/api/2/group/member'
        self.log.debug(f"{group_names}")
        url = self.base_url + rel_url
        errors = []
        for group_name in group_names:
            url_params = {'groupname': group_name}
            r = self.session.get(url=url, params=url_params)
            if r.status_code == 404:
                errors.append(', '.join(r.json()['errorMessages']))
            else:
                r.raise_for_status()
        self.log.debug(f"returned error: {errors}")
        return errors

    def get_users_from_group(self, group_name) -> List[JiraUser]:
        rel_url = '/rest/api/2/group/member'
        self.log.debug(group_name)
        is_last_page = False
        url = self.base_url + rel_url
        start_at = 0
        users = []
        while not is_last_page:
            url_params = {
                'groupname': group_name,
                'includeInactiveUsers': True,
                'startAt': start_at
            }
            r = self.session.get(url=url, params=url_params)
            r.raise_for_status()
            for user_json in r.json()['values']:
                users.append(JiraUser.from_json(user_json))
            is_last_page = r.json()['isLast']
            start_at += r.json()['maxResults']
        return users

    def get_users_from_groups(self, group_names) -> List[JiraUser]:
        self.log.debug(group_names)
        users = []
        for group_name in group_names:
            users.extend(self.get_users_from_group(group_name))
        return users

    def get_inactive_users(self, excluded_users: List[JiraUser]) -> List[JiraUser]:
        """Return inactive users not in any of the exclude_groups and not yet anonymized.

        Already anonymized users have the e-mail-address '@jira.invalid'.

        The query-possibilities of '/rest/api/2/user/search' are limited:
        A 'username' must be given; no wildcard is documented (by Atlassian),
        and there is no exclude-pattern.

        The 'username' is "A query string used to search username, name or e-mail
        address". But in fact there are 'wildcard'-characters documented in
        JRASERVER-29069. Didn't check the Jira source-code so far.
        These are:
            o "" (double quotes)
            o '' (single quotes)
            o . (dot)
            o % (percent)
            o _ (underscore)

        To give a dummy 'username', I use '.' here.

        The resulting REST-call is something like:
        `/rest/api/2/user/search?username=.&includeInactive=true&includeActive=false&startAt=...`.

        This function uses the REST API `/rest/api/2/user/search`. There is an open Jira-bug documented
        in [JRASERVER-29069](https://jira.atlassian.com/browse/JRASERVER-29069) which leads (in some
        Jira instances) to a max. of 1000 users. I have seen this bug in some instances, but others
        delivered more than 1000.

        If the number of returned users is exact 1000, it is likely you ran into the bug RASERVER-29069.
        """

        excluded_user_names = [user.name for user in excluded_users]
        self.log.debug(f" Excluded users: {excluded_user_names}")

        rel_url = '/rest/api/2/user/search'
        self.log.debug("")
        is_beyond_last_page = False
        url = self.base_url + rel_url
        start_at = 0
        num_users_so_far = 0
        users = []
        self.execution_logger.logs['rest_user_search'] = {}
        page_no = 1
        # Query the paged API until an empty page.
        while not is_beyond_last_page:
            url_params = {
                'username': '.',
                'includeActive': False,
                'includeInactive': True,
                # 'maxResults': max_results,
                'startAt': start_at}
            r = self.session.get(url=url, params=url_params)
            self.log.debug(self.serialize_response(r, False))
            self.execution_logger.logs['rest_user_search'][f'page_{page_no}'] = \
                self.serialize_response(r, True)
            page_no += 1
            r.raise_for_status()
            num_users_so_far += len(r.json())
            self.log.debug(f"; num_users_so_far {num_users_so_far}")
            if len(r.json()) == 0:
                is_beyond_last_page = True
                # Warning about JRASERVER-29069.
                if num_users_so_far == 1000:
                    self.log.warning(
                        f"The REST API '{rel_url}' returned exact 1000 users."
                        " This could mean you ran into JRASERVER-29069."
                        " In that case there could be more inactive users.")
                continue
            start_at += len(r.json())

            for user_json in r.json():
                user = JiraUser.from_json(user_json)
                if user.name in excluded_user_names or user.email_address.find('@jira.invalid') >= 0:
                    continue
                user = JiraUser.from_json(user_json)
                if user not in users:
                    users.append(user)
        return users

    def get_anonymization_validation_data(self, user: JiraUser):
        rel_url = '/rest/api/2/user/anonymization'
        # The function name 'get_anonymization_validation_data' exists twice. One time here and
        # one time in ValidateCmdExecutor-class. This will result in logging this name twice if
        # log-level is DEBUG.
        self.log.debug(f"for user-key '{user.name}'")
        url = self.base_url + rel_url
        url_params = {'userKey': user.key}
        if self.config.effective_config['is_expand_validation_with_affected_entities']:
            url_params['expand'] = 'affectedEntities'
        r = self.session.get(url=url, params=url_params)
        return r

    def anonymize_user(self, user_key, new_owner_key):
        rel_url = '/rest/api/2/user/anonymization'
        url = self.base_url + rel_url
        body = {"userKey": user_key, "newOwnerKey": new_owner_key}
        r = self.session.post(url=url, json=body)
        return r

    def trigger_reindex(self):
        """Trigger a background reindex.

        Note,
        from https://confluence.atlassian.com/jirakb/reindex-jira-server-using-rest-api-via-curl-command-663617587.html:

        "For JIRA DC a better approach than background indexing is to take one node out of the
        cluster and run FOREGROUND reindexing.
        See  JRASERVER-66969 - Discourage Background Indexing for Datacenter instances in Indexing
        Page CLOSED"
        """

        # Also from
        # https://confluence.atlassian.com/jirakb/reindex-jira-server-using-rest-api-via-curl-command-663617587.html:
        #   - FOREGROUND - runs a lock/full reindexing
        #   - BACKGROUND - runs a background reindexing. If JIRA fails to finish the background
        #       reindexing, respond with 409 Conflict (error message).
        #   - BACKGROUND_PREFERRED  - If possible do a background reindexing. If it's not possible
        #       (due to an inconsistent index), do a foreground reindexing.
        url_params = {
            'type': 'BACKGROUND',
            'indexComments': True,
            'indexChangeHistory': True,
            'indexWorklogs': True
        }
        rel_url = '/rest/api/2/reindex?' + parse.urlencode(url_params)
        url = self.base_url + rel_url
        r = self.session.post(url=url)
        self.execution_logger.logs['rest_post_reindex'] = self.serialize_response(r)

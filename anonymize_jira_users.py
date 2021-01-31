#!/usr/bin/env python3

# Copyright 2021 Johannes Heger
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import atexit
import configparser
import csv
import json
import locale
import logging
import os
import pathlib
import re
import sys
import textwrap
import time
from datetime import datetime, timedelta
from json.decoder import JSONDecodeError
from urllib import parse

import requests
import urllib3

#
# Global constants: Defaults
#
# Defaults comprise of a dictionary and some variables. The dictionary is also taken to generate an example-
# configuration with command line option -g.
# All configurations which must not configurable by the user are global constants.
#

# This is not a valid Python-version, but who cares.
__version__ = '1.0.0-SNAPSHOT'

CMD_INACTIVE_USERS = 'inactive-users'
CMD_ANONYMIZE = 'anonymize'
# The validate-command is a subset of the anonymize-command. They share a lot of code and the "anonymization"-reports.
CMD_VALIDATE = 'validate'
CMD_MISC = 'misc'

DEFAULT_CONFIG = {
    # The subparser-name as a default of None is technically not needed. But it is useful to place this dict-entry at
    # the top-position at option --info.
    'subparser_name': None,
    'jira_base_url': '',
    'jira_auth': '',
    'exclude_groups': [],
    'user_list_file': '',
    'encoding': None,
    'report_out_dir': '.',
    'loglevel': 'INFO',
    'is_expand_validation_with_affected_entities': False,
    'is_dry_run': False,
    'new_owner': '',
    'initial_delay': 10,
    'regular_delay': 3,
    'timeout': 0,
    'is_trigger_background_reindex': False,
}

REPORT_BASENAME = 'anonymizing_report'
TEMPLATE_FILENAME = 'my-bare-default-config.cfg'
INACTIVE_USERS_OUTFILE = 'inactive-users.cfg'

SSL_VERIFY = False
LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
PRETTY_PRINT_LOG_LEVELS = "{}".format(LOG_LEVELS).replace('[', '').replace(']', '').replace('\'', '')
# These values for false and true are taken from the docs of Python
# configParser.getboolean().
# But in configParser, there are also values 0 for false and 1 for true described.
# But the Anonymizer allows integers as values, which shall not be interpreted as
# booleans. Therefore 0 and 1 are ignored as booleans here.
BOOLEAN_FALSE_VALUES = ['no', 'false', 'off']
BOOLEAN_TRUE_VALUES = ['yes', 'true', 'on']

#
# Global vars.
#

log = logging.getLogger()

# The global config is created by:
#  - the DEFAULT_CONFIG
#  - the config-file, if given. The parameters in the config-file overwrites the default-config.
#  - the command-line-arguments. These overwrite the parameters set so far.
g_config = DEFAULT_CONFIG

# The keys are:
#   - script_started
#   - rest_get_mypermissions
#   - rest_get_	user__new_owner
#   - rest_get_anonymization_progress__before_anonymization
#   - rest_auditing
#   - rest_post_reindex
#   - script_finished
#   - is_script_aborted
#   - script_execution_time
g_execution = {}

# The user data.
#   - key: user-name
#   - value:
#       - rest_get_user__before_anonymization
#       - rest_get_anonymization__query_validation
#       - user_filter
#           - error_message
#           - is_anonymize_approval
#       - rest_post_anonymization
#       - rest_get_anonymization_progress
#       - anonymized_data_from_rest
g_users = {
    # 'doc': 'This is for collecting user-related data during execution.'
}

# The collected data. This is something like an internal trace-log.
# The reports will be generated from this.
# The keys are:
#   - effective_config
#   - execution: Information about script-execution not specific to users.
g_details = {
    'effective_config': g_config,
    'execution': g_execution,
    'users_from_user_list_file': g_users
}

g_session = requests.Session()
# Suppress annoying warning.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_sanitized_global_details():
    """The details contain the jira_auth-information. This must not be part of any log or report.

    :return: The sanitized details.
    """
    sanitized_details = g_details.copy()
    sanitized_details['effective_config']['jira_auth'] = '<sanitized>'
    return sanitized_details


def merge_dicts(d1, d2):
    """Merge d2 into d1. Take only non-None-properties into account.
    :param d1: The dict d2 is merged to.
    :param d2: The dict to be merged to d1
    :return: None
    """
    res = d1.copy()
    for k, v in d2.items():
        if v is not None:
            res[k] = v
    d1.clear()
    d1.update(res)


def validate_auth_parameter(auth):
    """Check parameter 'auth' for valid auth-type 'Basic' or 'Bearer, extract the auth-data, and return them.
    :param auth: Expected is either something like 'Basic user:pass', or
                'Bearer NDcyOTE1ODY4Nzc4Omj+FiGVuLh/vs4WjTS9/3lGaysM'
    :return:
        1 - Error-message in case the auth couldn't be parsed properly. None otherwise.
        2 - The auth-type 'basic' or 'bearer' (lower case).
        3 - In case of 'basic': The user-name. In case of 'bearer': The token.
        4 - In case of 'basic': The password. In case  of 'bearer': None.
    """

    # Split 'Basic' or 'Bearer' from the rest.
    auth_parts = re.split(r'\s+', auth, 1)

    if len(auth_parts) < 2:
        return "Invalid format in authentication parameter.", None, None, None

    auth_type = auth_parts[0].lower()
    if not auth_type.lower() in ['basic', 'bearer']:
        return "Invalid authentication type '{}'. Expect 'Basic' or 'Bearer'.".format(auth_type), None, None, None

    username = None
    password = None
    if auth_type == 'basic':
        # Split only at the first colon, as a colon could be part of the password.
        name_and_password = re.split(r':', auth_parts[1], 1)
        if len(name_and_password) != 2:
            return "Invalid format for 'Basic' in authentication argument.", None, None, None
        else:
            username = name_and_password[0]
            password = name_and_password[1]

    token = None
    if auth_type == 'bearer':
        if len(auth_parts) != 2:
            return "Invalid format for 'Bearer' in authentication argument.", None, None, None
        else:
            token = auth_parts[1]

    return \
        None, \
        auth_type, \
        username if auth_type == 'basic' else token, \
        password if auth_type == 'basic' else None


def setup_http_session(auth_type, user_or_bearer, passwd):
    g_session.verify = SSL_VERIFY
    g_session.headers = {
        'Content-Type': 'application/json'
    }
    if auth_type == 'basic':
        g_session.auth = (user_or_bearer, passwd)
        url = g_config['jira_base_url'] + '/rest/auth/1/session'
        # Expect 200 OK here.
        r = g_session.get(url=url)
        if r.status_code != 200:
            error_message = "Auth-check returned {}".format(r.status_code)
            if r.status_code == 403:
                error_message += ". This could mean there is a CAPCHA."
            return error_message
    else:
        g_session.headers = {
            'Authorization': 'Bearer ' + user_or_bearer,
            'Content-Type': 'application/json'
        }
    return ""


def check_for_admin_permission():
    """Check if the user can log-in and is an administrator.

    In Jira there are two levels of administration: The Administrator and the System Administrator. The weaker
    Administrator is sufficient for anonymization. To check against administrator-permissions, call the
    GET /rest/api/2/mypermissions API. This returns among others the "ADMINISTR" and the "SYSTEM_ADMIN" entries.
    Check for permissions["ADMINISTER"]["havePermission"]==True. System-admins have both set to true.

    {
        ...,
        "permissions": {
            "ADMINISTER": {
                "id": "0",
                "key": "ADMINISTER",
                "name": "Jira Administrators",
                "type": "GLOBAL",
                "description": "Ability to perform most administration functions (excluding Import & Export, SMTP Configuration, etc.).",
                "havePermission": true
            },
            "SYSTEM_ADMIN": {
                "id": "44",
                "key": "SYSTEM_ADMIN",
                "name": "Jira System Administrators",
                "type": "GLOBAL",
                "description": "Ability to perform all administration functions. There must be at least one group with this permission.",
                "havePermission": false
            },
        }
    }
    :return: If the auth-user can log-in and is an administrator.
    """
    rel_url = '/rest/api/2/mypermissions'
    url = g_config['jira_base_url'] + rel_url
    r = g_session.get(url=url)
    g_execution['rest_get_mypermissions'] = {}
    g_execution['rest_get_mypermissions'] = serialize_response(r, False)
    error_message = ""
    if r.status_code == 200:
        # Supplement a reduced JSON, as the whole JSON is very large but most of it is not of interest.
        g_execution['rest_get_mypermissions']['json'] = {}
        g_execution['rest_get_mypermissions']['json']['permissions'] = {}
        g_execution['rest_get_mypermissions']['json']['permissions']['ADMINISTER'] = \
            r.json()['permissions']['ADMINISTER']
        # Now check if the executing user has the appropriate permission.
        if not r.json()['permissions']['ADMINISTER']['havePermission']:
            error_message = "Permisson-check: User is not an administrator." \
                            " Only roles Administrator and System-Admins are allowed to anonymize users."
    elif r.status_code == 401:
        # The r.text() is a complete HTML-Page an too long to read in a console. Shorten it to a one-liner.
        error_message = "Permisson-check returned 401 Unauthorized."
    elif r.status_code == 403:
        # The r.text() is a complete HTML-Page an too long to read in a console. Shorten it to a one-liner.
        error_message = "Permisson-check returned 403 Forbidden."
    else:
        # The documented error-codes are as follows. But they are not expected here because no query is made for
        # an issue or a project, nor for behalf of any user.
        #   - 400 Returned if the project or issue id is invalid.
        #   - 401 Returned if request is on behalf of anonymous user.
        #   - 404 Returned if the project or issue id or key is not found.
        error_message = "Permisson-check GET /rest/api/2/mypermissions returned {} with message {}.".format(
            r.status_code,
            r.text)
    return error_message


def get_jira_serverinfo():
    rel_url = '/rest/api/2/serverInfo'
    url = g_config['jira_base_url'] + rel_url
    r = g_session.get(url=url)
    g_execution['rest_get_serverInfo'] = serialize_response(r)
    r.raise_for_status()


def is_jira_version_less_then(major, minor):
    version_numbers = g_execution['rest_get_serverInfo']['json']['versionNumbers']
    # versionNumbers is e.g. [8,14,0]
    is_less_then = version_numbers[0] < major or (version_numbers[0] == major and version_numbers[1] < minor)
    log.debug("{}.{}: {}".format(major, minor, is_less_then))
    return is_less_then


def write_default_cfg_file(config_template_filename):
    with open(config_template_filename, 'w') as f:
        help_text = """        ####
        #
        # Configuration for {scriptname}
        #
        # General:
        #   - These values are true in any notation: {boolean_true}.
        #   - These values are false in any notation: {boolean_false}.
        #
        ####

        [DEFAULT]

        #   Loglevel. Valid levels are {valid_loglevels}.
        #   The given value is the default.
        #loglevel = {loglevel}
        #   Jira base-URL.
        #   The given value is an example.
        #jira_base_url = http://localhost:2990/jira
        #   Admin user-authentication. Two auth-types are supported: Basic, and Bearer (staring with Jira 8.14).
        #       - The format for Basic is:   Basic <user>:<pass>
        #       - The format for Bearer is:  Bearer <token>
        #   The given values are examples.
        #jira_auth = Basic admin:admin
        #jira_auth = Bearer NDcyOTE1ODY4Nzc4Omj+FiGVuLh/vs4WjTS9/3lGaysM
        #   Exclude members of these groups at command 'inactive-users'.
        #   Each group must appear on its own line (except the first one), and must be indented.
        #   The given values are examples.
        #exclude_groups = group1
        #  group2
        #  group with spaces
        #   File with user-names to be anonymized or just validated. One user-name per line. 
        #   Comments are allowed: They must be prefixed by '#' and they must appear on their own line.
        #   The character-encoding is platform dependent Python suggests.
        #   If you have trouble with the encoding, try out the parameter '--encoding'.
        #   The given value is an example.
        #user_list_file = users.cfg
        #   Force a character-encoding for reading the user_list_file. Empty means platform dependent Python suggests.
        #   If you run on Win or the user_list_file was created on Win, try out one of these encodings:
        #     utf-8, cp1252, latin1 
        #   The given value is an example.
        #encoding = utf-8
        #   Output-directory to write the reports into.
        #report_out_dir = {report_out_dir}
        #   Include 'affectedEntities' in the validation result. This is only for documentation 
        #   to enrich the detailed report. It doesn't affect the anonymization.
        #   Doing so could increase significantly execution time.
        #   The given value is the default.
        #is_expand_validation_with_affected_entities = {is_expand_validation_with_affected_entities}
        #   Finally do not anonymize. To get familiar with the script and to test it.
        #   The given value is the default.
        #is_dry_run = {is_dry_run}
        #   Transfer roles to the user with this user-name.
        #   The given value is an example.
        #new_owner = new-owner
        #   Initial delay in seconds the Anonymizer waits after the anonymization is
        #   triggered and the first call to get the anonymization-progress.
        #   The default of Jira is {initial_delay} seconds, and this is also the default of the Anonymizer.
        #initial_delay = {initial_delay}
        #   The delay in seconds between calls to get the anonymization-progress.
        #   The default of Jira is {regular_delay} seconds, and this is also the default of the Anonymizer.
        #regular_delay = {regular_delay}
        #   Time in seconds the anonymization shall wait to be finished.
        #   0 (or any negative value) means: Wait as long as it takes.
        #   The given value is the default.
        #timeout = {timeout}
        #   If at least one user was anonymized, trigger a background re-index.
        #   The given value is the default.
        #is_trigger_background_reindex = {is_trigger_background_reindex}
        """.format(scriptname=os.path.basename(__file__),
                   boolean_true=BOOLEAN_TRUE_VALUES,
                   boolean_false=BOOLEAN_FALSE_VALUES,
                   valid_loglevels=PRETTY_PRINT_LOG_LEVELS,
                   loglevel=g_config['loglevel'],
                   report_out_dir=g_config['report_out_dir'],
                   is_expand_validation_with_affected_entities=
                                       g_config['is_expand_validation_with_affected_entities'],
                   is_dry_run=g_config['is_dry_run'],
                   initial_delay=g_config['initial_delay'],
                   regular_delay=g_config['regular_delay'],
                   timeout=g_config['timeout'],
                   is_trigger_background_reindex=g_config['is_trigger_background_reindex'])
        f.write(textwrap.dedent(help_text))


def read_configfile_and_merge_into_global_config(args):
    """Read the config-file and merge it into the global defaults-dict.

    The values within a ConfigParser are always strings. After a merge with a Python dict, the expected types could
    be gone. E.g. if a boolean is expected, but the ConfigParser delivers the string "false", this string is
    True.
    This function additionally converts all read parameters to Python-types.
    :param args: The arguments got from the command-line.
    :return: Nothing.
    """
    parser = configparser.ConfigParser()
    # The parser could read the file by itself by calling parser.read(args.config_file). But if the file doesn't exist,
    # the parser uses an empty dict silently. The open() is to throw an error in case the file can't be opened.
    with open(args.config_file) as f:
        parser.read_file(f)
    defaults = parser.defaults()

    # parser.defaults() is documented as dict, but it is something weird without an .items()-function.
    # A copy of the defaults solve this problem.
    defaultz = dict(defaults)
    real_dict = {}
    for k, v in defaultz.items():
        if k.lower() == 'exclude_groups':
            groups = re.split('[\\n\\r]+', v)
            real_dict[k] = groups
        elif v.lower() in BOOLEAN_TRUE_VALUES:
            real_dict[k] = True
        elif v.lower() in BOOLEAN_FALSE_VALUES:
            real_dict[k] = False
        else:
            try:
                real_dict[k] = int(v)
            except ValueError:
                # This value must be a string-value, because other types are processed so far.
                # Take it only if not empty. This is important because merge_dicts() ignores only None-values, but
                # takes into account empty strings. The ConfigParser delivers empty strings for not-set values,
                # e. g.
                #   loglevel =
                # is equal to
                #   loglevel = ''
                # But because loglevel is not None, the value '' would overwrite the default-value INFO. As as result,
                # the loglevel wouldn't be set at all and would lead to an error in set_loglevel().
                # The loglevel is only an example. This would become a problem for several attributes.
                if v:
                    real_dict[k] = v

    merge_dicts(g_config, real_dict)


def set_logging():
    # Set basicConfig() to get levels less than WARNING running in our logger.
    # See https://stackoverflow.com/questions/56799138/python-logger-not-printing-info
    logging.basicConfig(level=logging.WARNING)
    # Set a useful logging-format. Not the most elegant way, but it works.
    log.handlers[0].setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(funcName)s(): %(message)s'))
    # See also https://docs.python.org/3/howto/logging.html:
    numeric_level = getattr(logging, g_config['loglevel'], None)
    # The check for valid values have been done in parser.add_argument().
    log.setLevel(numeric_level)

    # Adjust logging-level of module "urllib3". If our logging is set to DEBUG, that also logs in that level.
    logging.getLogger("urllib3").setLevel(logging.WARNING)


class PathAction(argparse.Action):
    """Make a clean path: strip off trailing or multiple path-separators."""

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(PathAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        # print('%r %r %r' % (namespace, values, option_string))
        values = str(pathlib.Path(values))
        setattr(namespace, self.dest, values)


def parse_parameters():
    g_config['report_details_filename'] = REPORT_BASENAME + '_details.json'
    g_config['report_json_filename'] = REPORT_BASENAME + '.json'
    g_config['report_text_filename'] = REPORT_BASENAME + '.csv'
    script_name = os.path.basename(__file__)

    #
    # Part 1: Define and parse the arguments.
    #
    # All actions with 'store_true' must have a default=None. This is important for the configuration chaining of
    # the DEFAULT_CONFIG, the config-file, and the args.
    #
    epilog = """    How to start
    
    o Create the file usernames.txt with the user-names to be anonymized, one 
      user-name per line.
    o Create a config-file-template:
          {script_name} misc -g
      The file my-bare-default-config.cfg has been created.
    o Rename the file, e.g. to my-config.cfg.
    o In that file, set the attributes jira_base_url, jira_auth with
      format 'Basic admin:admin', user_list_file = usernames.txt, new_owner.
    o Call
          {script_name} validate -c my-config.cfg
      to see what would happen in case of anonymizing.
    o Call
          {script_name} anonymize -c my-config.cfg
      to execute anonyization.
    o Have a look at the report {anonymization_report_csv}. More details about the
      users are given in {anonymization_report_details_json}.
    """.format(script_name=script_name, anonymization_report_csv=g_config['report_text_filename'],
               anonymization_report_details_json=g_config['report_details_filename'])
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="The Anonymizer is a Python3-script to help Jira-admins"
                                                 " anonymizing Jira-users in bulk.",
                                     epilog=textwrap.dedent(epilog))
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('-l', '--loglevel', choices=LOG_LEVELS,
                               help="Log-level. Defaults to {}.".format(DEFAULT_CONFIG['loglevel']))

    #
    # Arguments common to 'anonymize', 'inactive-users', and 'validate'.
    #
    parent_parser_for_anonymize_and_inactiveusers_and_validate = argparse.ArgumentParser(add_help=False)
    parent_parser_for_anonymize_and_inactiveusers_and_validate \
        .add_argument('-c', '--config-file',
                      help="Config-file to pre-set command-line-options."
                           " You can generate a config-file-template with option 'misc -g'."
                           " There are parameters in the config-file not present on the command line."
                           " Empty parameters in the config-file are ignored."
                           " Parameters given on the command line overwrite parameters"
                           " given in the config-file. ")
    parent_parser_for_anonymize_and_inactiveusers_and_validate \
        .add_argument('-b', '--jira-base-url', help="Jira base-URL.")
    parent_parser_for_anonymize_and_inactiveusers_and_validate \
        .add_argument('-a', '--jira-auth', metavar='ADMIN_USER_AUTH',
                      help="Admin user-authentication."
                           " Two auth-types are supported: Basic, and Bearer (starting with Jira 8.14)."
                           " The format for Basic is: 'Basic <user>:<pass>'."
                           " The format for Bearer is: 'Bearer <token>'.")
    parent_parser_for_anonymize_and_inactiveusers_and_validate \
        .add_argument('-o', '--report-out-dir', action=PathAction,
                      help="Output-directory to write the reports into."
                           " If it doesn't exist, it'll be created."
                           " If you'd like the date included,"
                           " give something like `date +%%Y%%m%%d-%%H%%M%%S-anonymize-instance1`."
                           " Defaults to '{}'.".format(DEFAULT_CONFIG['report_out_dir']))

    parent_parser_for_anonymize_and_inactiveusers_and_validate_post = argparse.ArgumentParser(add_help=False)
    parent_parser_for_anonymize_and_inactiveusers_and_validate_post \
        .add_argument('--info', action='store_true', default=None,
                      help="Print the effective config, and the character-encoding Python suggests, then exit.")

    #
    # Arguments common to 'anonymize' and 'validate'.
    #
    parent_parser_for_anonymize_and_validate = argparse.ArgumentParser(add_help=False)
    parent_parser_for_anonymize_and_validate \
        .add_argument('-i', '--user-list-file',
                      help="File with user-names to anonymize or just to validate."
                           " One user-name per line. Comments are allowed:"
                           " They must be prefixed by '#' and they must appear on their own line."
                           " The character-encoding is platform dependent Python suggests."
                           " If you have trouble with the encoding, try out the parameter '--encoding'.")
    parent_parser_for_anonymize_and_validate \
        .add_argument('--encoding', metavar='ENCODING',
                      help="Force a character-encoding for reading the user-list-file."
                           " Empty means platform dependent Python suggests."
                           " If you run on Win or the user-list-file was created on Win,"
                           " try out one of these encodings: utf-8, cp1252, latin1.")
    parent_parser_for_anonymize_and_validate \
        .add_argument('--expand-validation-with-affected-entities', action='store_true', default=None,
                      dest='is_expand_validation_with_affected_entities',
                      help="Include 'affectedEntities' in the validation result."
                           " This is only for documentation to enrich the detailed report."
                           " It doesn't affect the anonymization."
                           " Doing so could increase significantly execution time.")

    sp = parser.add_subparsers(dest='subparser_name')

    sp_inactive_users = sp.add_parser(CMD_INACTIVE_USERS,
                                      parents=[parent_parser,
                                               parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                               parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                      help="Retrieves a list of inactive, not-yet anonymized users."
                                           " These users are candidates for anonymization.")
    sp_inactive_users.add_argument('-G', '--exclude-groups', nargs='+',
                                   help="Exclude members of these groups."
                                        " Multiple groups must be space-separated."
                                        " If a group contains spaces, the group must be enclosed"
                                        " in single or double quotes.")
    sp_validate = sp.add_parser(CMD_VALIDATE,
                                parents=[parent_parser,
                                         parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                         parent_parser_for_anonymize_and_validate,
                                         parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                help="Validates user anonymization process.")
    sp_anonymize = sp.add_parser(CMD_ANONYMIZE,
                                 parents=[parent_parser,
                                          parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                          parent_parser_for_anonymize_and_validate,
                                          parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                 help="Anonymizes users.")
    sp_misc = sp.add_parser(CMD_MISC, parents=[parent_parser],
                            help="Intended to bundle diverse functions."
                                 " Currently `-g` to generate a template-config-file is the only function.")

    #
    # Add arguments special to command "anonymize".
    #
    sp_anonymize.add_argument('-D', '--dry-run', action='store_true', default=None,
                              dest='is_dry_run',
                              help="Finally do not anonymize. To get familiar with the script and to test it.")
    sp_anonymize.add_argument('-n', '--new-owner',
                              help="Transfer roles of all anonymized users to the user with this user-name.")
    sp_anonymize.add_argument('-x', '--background-reindex', action='store_true', default=None,
                              dest='is_trigger_background_reindex',
                              help="If at least one user was anonymized, trigger a background re-index.")

    #
    # Add arguments special to command "misc".
    #
    sp_misc.add_argument('-g', '--generate-config-template', metavar='CONFIG_TEMPLATE_FILE',
                         const=TEMPLATE_FILENAME, nargs='?',
                         dest='config_template_filename',
                         help="Generate a configuration-template. Defaults to {}.".format(
                             TEMPLATE_FILENAME))

    parser.parse_args()
    args = parser.parse_args()

    #
    # Part 2: Check arguments, print help or error-message if needed, and exit in case of errors.
    #

    # Print help if no argument is given.
    # sys.argv at least contains the script-name, so it has at least the length of 1.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    if args.subparser_name == CMD_MISC:
        if args.config_template_filename:
            write_default_cfg_file(args.config_template_filename)
            sys.exit(0)
        # elif args.recreate_report:
        #     recreate_reports()
        #     sys.exit(0)
        else:
            # sp_misc.error("Command 'misc' needs '-g' or '--recreate-report'")
            sp_misc.error("Command '{}' needs '-g'".format(CMD_MISC))

    # In a config-file is given, merge it into the global config. Non-None-values overwrites the values present so far.
    # Note, a config-file can only be present for the sub-parsers.
    if (args.subparser_name in [CMD_ANONYMIZE, CMD_INACTIVE_USERS, CMD_VALIDATE]) and args.config_file:
        read_configfile_and_merge_into_global_config(args)

    # Merge command line arguments in and over the global config. Non-None-values overwrites the values present so far.
    merge_dicts(g_config, vars(args))

    g_config['locale_getpreferredencoding'] = '{}'.format(locale.getpreferredencoding())
    g_config['sys_getfilesystemencoding'] = '{}'.format(sys.getfilesystemencoding())

    errors = []
    #
    # Checks for 'anonymize', 'inactive-users', and 'validate'.
    #
    if args.subparser_name in [CMD_ANONYMIZE, CMD_INACTIVE_USERS, CMD_VALIDATE]:
        if args.info:
            gd = get_sanitized_global_details()
            print("Effective config:\n{}".format(json.dumps(gd['effective_config'], indent=4)))
            print("")
            sys.exit(0)

        if not g_config['jira_base_url']:
            errors.append("Missing jira-base-url")
        else:
            # Remove trailing slash if present.
            g_config['jira_base_url'] = g_config['jira_base_url'].rstrip('/')

        if not g_config['jira_auth']:
            errors.append("Missing authentication")

        auth_error, auth_type, user_or_bearer, password = validate_auth_parameter(g_config["jira_auth"])
        if auth_error:
            errors.append(auth_error)
        else:
            error_message = setup_http_session(auth_type, user_or_bearer, password)
            if error_message:
                errors.append(error_message)
            else:
                error_message = check_for_admin_permission()
                if error_message:
                    errors.append(error_message)
                else:
                    get_jira_serverinfo()

        if len(errors) > 0:
            parent_parser_for_anonymize_and_inactiveusers_and_validate.error('; '.join(errors))

    if args.subparser_name in [CMD_ANONYMIZE, CMD_VALIDATE]:
        # Check if user_list_file does exist.
        if not g_config['user_list_file']:
            errors.append("Missing user-list-file")
        else:
            try:
                open(g_config['user_list_file'])
            except IOError:
                errors.append(
                    "User-list-file {} does not exist or is not accessible".format(g_config['user_list_file']))

    if args.subparser_name == CMD_ANONYMIZE:
        if not g_config['new_owner']:
            sp_anonymize.error("Missing new_owner.")
        else:
            r = get_user_data_of_existent_user(g_config['new_owner'])
            # TODO Check if the user is not deleted and is active.
            if r.status_code != 200:
                if r.status_code == 404:
                    sp_anonymize.error(r.json()['errorMessages'])
                else:
                    r.raise_for_status()

    if args.subparser_name == CMD_INACTIVE_USERS:
        try:
            # exclude_groups could be absent.
            errors = check_if_groups_exist(g_config['exclude_groups'])
        except KeyError:
            pass
        if len(errors) > 0:
            print("{}".format(errors))
            sp_inactive_users.error(', '.join(errors))

    set_logging()

    gd = get_sanitized_global_details()
    log.debug("Effective config: {}".format(gd['effective_config']))
    log.debug(("getpreferredencoding {}, getfilesystemencoding {}".format(locale.getpreferredencoding(),
                                                                          sys.getfilesystemencoding())))

    return args


def read_users_from_user_list_file():
    """Read the Jira user-names from the user-names-file. Skip lines starting with hash '#'.

    :return: None.
    """
    log.info("{}".format(g_config["user_list_file"]))
    with open(g_config["user_list_file"], 'r', encoding=g_config['encoding']) as f:
        user_list_file = f.read()
        lines = re.split('[\n\r]+', user_list_file)
        for line in lines:
            line = line.strip()
            # Skip comment lines.
            if line and not line.startswith('#'):
                user_name = line
                g_users[user_name] = {}
    log.info("The user-names are ({}): {}".format(len(g_users.keys()), list(g_users.keys())))


def serialize_response(r, is_include_json_response=True):
    """Serialize a requests-response to a JSON.

    With is_include_json_response the caller can suppress serialization in case of large and not interesting responses.

    :param r: The response of a requests.get(), requests.post(), ...
    :param is_include_json_response: True (default), if the response.json() shall be included in the serialied result.
    :return:
    """
    # The body is a b'String in Python 3 and is not readable by json.dumps(). It has to be decoded before.
    # The 'utf-8' is only a suggestion here.
    decoded_body = r.request.body.decode('utf-8') if r.request.body else None
    try:
        r_json = r.json()
    except JSONDecodeError:
        r_json = None

    j = {'status_code': r.status_code, 'requst_body': decoded_body, 'requst_method': r.request.method,
         'requst_url': r.request.url}

    if is_include_json_response:
        j['json'] = r_json

    return j


def get_user_data_of_existent_user(user_name):
    rel_url = '/rest/api/2/user'
    log.info("for user {}".format(user_name))
    url = g_config['jira_base_url'] + rel_url
    url_params = {'username': user_name}
    r = g_session.get(url=url, params=url_params)
    g_execution['rest_get_user__new_owner'] = serialize_response(r)
    log.debug(g_execution['rest_get_user__new_owner'])
    return r


def get_users_data(users):
    rel_url = '/rest/api/2/user'
    log.info("for {} users".format(len(users)))
    url = g_config['jira_base_url'] + rel_url
    for user_name in users.keys():
        url_params = {'includeDeleted': True, 'username': user_name}
        r = g_session.get(url=url, params=url_params)
        users[user_name]['rest_get_user__before_anonymization'] = serialize_response(r)
        log.debug(users[user_name]['rest_get_user__before_anonymization'])


def get_anonymization_validation_data(users):
    rel_url = '/rest/api/2/user/anonymization'
    log.info("")
    url = g_config['jira_base_url'] + rel_url
    for user_name, user_data in users.items():
        if user_data['rest_get_user__before_anonymization']['status_code'] != 200:
            # The user does not exist. A message about this missing user is logged later on
            # in filter_users().
            continue

        user_key = user_data['rest_get_user__before_anonymization']['json']['key']
        url_params = {'userKey': user_key}
        if g_config['is_expand_validation_with_affected_entities']:
            url_params['expand'] = 'affectedEntities'
        # https://docs.atlassian.com/software/jira/docs/api/REST/8.13.0/#api/2/user-getUser
        r = g_session.get(url=url, params=url_params)
        g_users[user_name]['rest_get_anonymization__query_validation'] = serialize_response(r)
        log.debug(g_users[user_name]['rest_get_anonymization__query_validation'])

        # These status-codes are documented:
        #  - 200 Returned when validation succeeded.
        #  - 400 Returned if a mandatory parameter was not provided or validation failed.
        #  - 403 Returned if the logged-in user cannot anonymize users
        if not (r.status_code == 200 or r.status_code == 400 or r.status_code == 403):
            # For all other not documented HTTP-problems:
            r.raise_for_status()


def filter_users(users):
    log.info("by existence and and anonymizaton-validation-data")

    for user_name, user_data in users.items():
        error_message = ""

        #
        # Give anonymize-approval only to users who are inactive or deleted.
        # A user can be 1. active, 2. inactive, or 3. deleted. So we have to check only if the user
        # is an active users to skip it.
        # A user is active, if GET rest/api/2/user responds with status code 200 OK and the
        # attribute "active" is true.
        #

        # Check if user-data could be retrieved.
        if user_data['rest_get_user__before_anonymization']['status_code'] != 200:
            error_message = '{}'.format(user_data['rest_get_user__before_anonymization']['json']['errorMessages'][0])
        else:
            # Check if the user is an active user:
            if user_data['rest_get_user__before_anonymization']['json']['active']:
                error_message = "Is an active user."

        #
        #  Check against validation result got from GET rest/api/2/user/anonymization.
        #
        if not error_message:
            # try/except: user_data['rest_get_anonymization__query_validation']
            # could be absent in case of an invalid user-name or -key in the user-name-file.
            try:
                if user_data['rest_get_anonymization__query_validation']['status_code'] != 200:
                    error_message = "HTTP status-code of the REST validation API is not 200. "
                # Regardless of the status code there could be validation-errors (seen e.g.
                # in use case "admin tries to anonymize themself": Status code was 400 Bad Request
                # and the error was "You can't anonymize yourself.").
                if len(user_data['rest_get_anonymization__query_validation']['json']['errors']) > 0:
                    error_message += "There is at least one validation error message."
            except KeyError:
                pass

        user_data['user_filter'] = {}
        user_data['user_filter']['error_message'] = ""
        if error_message:
            user_data['user_filter']['error_message'] = error_message
            user_data['user_filter']['is_anonymize_approval'] = False
            log.warning("{}: {}".format(user_name, error_message))
        else:
            user_data['user_filter']['is_anonymize_approval'] = True

    vu = {user_name: user_data for (user_name, user_data) in users.items() if
          user_data['user_filter']['is_anonymize_approval'] is True}
    log.info("{} users remain for anonymization: {}".format(len(vu.keys()), list(vu.keys())))


def get_anonymization_progress(user_name=None, full_progress_url=None):
    """Call the Get Progress API and check if there is an anonymization running and to get the progress.

    There are two reasons to do this:
        1. Before the first anonymization to check if there is any anonymization running. In this case both parameters
            user_name and full_progress_url must be None / absent.
        2. During our anonymization to check when it is finished. The latest response is stored for each user_name.

    When is an anonymization running, and when it is finished?

    Let's start with the HTTP status codes. 404 means "Returned if there is no user anonymization task found.". It is
    obvious there is no anonymization running. I can return something like "No anon. running".

    There is another status code documented: 403 "Returned if the logged-in user cannot anonymize users.". This is a
    problem the script has handled before the anonymization has been scheduled and is not checked here
    (in fact at the end of this function there is a r.raise_for_status() as a lifeline in case I haven't implemented
    a bullet-proof permission check earlier).

    There is the HTTP status code 200 left. If that is returned, I have to look into the JSON responses "status"-
    attribute. I haven't a mapping of HTTP status-code to progress "status"-attribute yet, by I have the list of
     "status" values read from the Jira source code
     (jira-project/jira-components/jira-plugins/jira-rest/jira-rest-plugin/src/main/java/com/atlassian/jira/rest/v2/user/anonymization/UserAnonymizationProgressBean.java):
    These are:
      - COMPLETED The anonymization process finished. Some errors or warnings might be present.
      - INTERRUPTED There is no connection with the node that was executing the anonymization process. Usually, this
            means that the node crashed and the anonymization task needs to be cleaned up from the cluster.
      - IN_PROGRESS The anonymization process is still being performed.
      - VALIDATION_FAILED The anonymization process hasn't been started because the validation has failed for some
            anonymization handlers.

    Note, I have seen a "status" "IN_PROGRESS" with a "currentProgress" of 100.

    As a conclusion I can say:

    HTTP status | "status" attribute| Anonymization not running (anymore) / is finished |   Anonymization is running
        404     |   don't care      |   Yes                                                     No
        200     |   IN_PROGRESS     |   No                                                      Yes
        200     |   other           |   Yes                                                     No

    The "errors" and "warnings" are not evaluated in this implementation step. Maybe later. I assume the validation
    does the job to show errors, and the filter_users() will filter users out in case of errors.

    :param user_name: Optional. Given if there have been scheduled one of our anonymizations. In this case, the
        full_progress_url is also mandatory.
    :param full_progress_url: Optional. Given if there have been scheduled one of our anonymizations. In this case,
        the user_name is also mandatory.
    :return:
        o The progress (percentage) from the returned JSON. 100 doesn't mean the "status" is also "COMPLETED".
        o -1: if HTTP-status is 404 ("Returned if there is no user anonymization task found.").
        o -2: if the "status" is "COMPLETED". I assume a "currentProgress" of 100.
        o -3: Other "status" than "IN_PROGRESS" and "COMPLETED". Means "not in progress".
    """
    log.debug("user_name {}, full_progress_url {}".format(user_name, full_progress_url))
    assert not (bool(user_name) ^ bool(full_progress_url))

    if full_progress_url:
        url = full_progress_url
        # Only DEBUG, because this could be called a lot.
        log.debug("Checking if specific anonymization for user '{}' is running".format(user_name))
    else:
        rel_url = '/rest/api/2/user/anonymization/progress'
        url = g_config['jira_base_url'] + rel_url
        log.info("Checking if any anonymization is running")
    r = g_session.get(url=url)
    # If this call is for a specific user/anonymization-task, store the response in the user's data.
    if user_name:
        g_users[user_name]['rest_get_anonymization_progress'] = serialize_response(r)
        log.debug(g_users[user_name]['rest_get_anonymization_progress'])
    else:
        g_execution['rest_get_anonymization_progress__before_anonymization'] = serialize_response(r)

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
        log.debug("progress_percentage {}%".format(progress_percentage))
    else:
        d = {-1: 'No user anonymization task found', -2: 'COMPLETED', -3: 'Not in progress'}
        log.debug("{}".format(d[progress_percentage]))

    # For any other HTTP status:
    if progress_percentage is None:
        r.raise_for_status()

    return progress_percentage


def wait_until_anonymization_is_finished_or_timedout(i, user_name):
    """Wait until the anonymization for the given user has been finished.
    :param user_name: The user-anonymization to wait for.
    :return: False if anonymization finished within the timeout. True otherwise (= timed out).
    """
    log.debug("for user {}: {}".format(i, user_name))
    user_data = g_users[user_name]
    url = g_config['jira_base_url'] + user_data['rest_post_anonymization']['json']['progressUrl']
    is_timed_out = True
    started_at = datetime.now()
    times_out_at = started_at + timedelta(seconds=g_config['timeout']) if g_config['timeout'] else None
    # Print progress once a minute.
    next_progress_print_at = started_at + timedelta(minutes=1)
    while times_out_at is None or datetime.now() < times_out_at:
        progress_percentage = get_anonymization_progress(user_name, url)
        # Any value <0 means "not in progress".
        if progress_percentage < 0:
            is_timed_out = False
            break
        if datetime.now() >= next_progress_print_at:
            log.info("Progress {}%".format(progress_percentage))
            next_progress_print_at += timedelta(minutes=1)
        time.sleep(g_config['regular_delay'])

    return is_timed_out


def anonymize_users(users_to_be_anonymized, new_owner_key):
    rel_url = '/rest/api/2/user/anonymization'

    log.info("Going to anonymize {} users".format(len(users_to_be_anonymized), rel_url))
    if g_config['is_dry_run']:
        log.warning("DRY-RUN IS ENABLED. No user will be anonymized.")

    url = g_config['jira_base_url'] + rel_url
    i = 0
    for user_name, user_data in users_to_be_anonymized.items():
        i += 1
        user_key = user_data['rest_get_user__before_anonymization']['json']['key']
        log.info("#{} (name/key): {}/{}".format(i, user_name, user_key))
        body = {"userKey": user_key, "newOwnerKey": new_owner_key}
        if not g_config['is_dry_run']:
            r = g_session.post(url=url, json=body)
            user_data['rest_post_anonymization'] = serialize_response(r)
            log.debug(user_data['rest_post_anonymization'])
            if r.status_code == 202:
                log.debug("Waiting the initial delay of {}s".format(g_config["initial_delay"]))
                time.sleep(g_config['initial_delay'])
                is_timed_out = wait_until_anonymization_is_finished_or_timedout(i, user_name)
                # Collecting the anonymized user-data is done before handling the timeout to save what still can
                # be saved.
                get_anonymized_user_data_from_audit_log(user_name)
                if is_timed_out:
                    log.error("Anonymizing of user '{}' took longer than the configured timeout of {} seconds."
                              " Abort script.".format(user_name, g_config['timeout']))
                    break
            else:
                # These error-status-codes are documented:
                #  - 400 Returned if a mandatory parameter was not provided.
                #  - 403 Returned if the logged-in user cannot anonymize users.
                #  - 409 Returned if another user anonymization process is already in progress.
                if r.status_code == 400 or r.status_code == 403 or r.status_code == 409:
                    log.error(
                        "A problem occurred scheduling anonymization user {}. See report {} for details.".format(
                            user_name, g_config['report_details_filename']))
                else:
                    # For all other, not documented HTTP-problems:
                    r.raise_for_status()


def is_anonymized_user_data_complete_for_user(user_name):
    """Check if all three items user-name, -key, and display-name are collected so far.
     If so, we're done with this user.
     """

    anonymized_data = g_users[user_name]['anonymized_data_from_rest']
    log.debug("anonymized_data so far for user {} is {}".format(user_name, anonymized_data))
    return anonymized_data['user_name'] \
           and anonymized_data['user_key'] \
           and anonymized_data['display_name']


def date_str_to_utc_str(date_str):
    """Convert date/time-string of format "2020-12-29T23:17:35.399+0100" to UTC in format 2020-12-29T23:16:35.399Z.

    :param date_str: Expect format "2020-12-29T23:17:35.399+0100"
    :return: String UTC in format 2020-12-29T23:16:35.399Z
    """
    # Split string in "2020-12-29T23:17:35" and ".399+0100".
    date_parts = date_str.split('.')
    # Convert to UTC. The conversion respects DST.
    date_utc = time.strftime("%Y-%m-%dT%H:%M:%S",
                             time.gmtime(time.mktime(time.strptime(date_parts[0], '%Y-%m-%dT%H:%M:%S'))))
    date_utc += '.{}Z'.format(date_parts[1][:3])
    return date_utc


def get_anonymized_user_data_from_audit_events(user_name_to_search_for):
    user_data = g_users[user_name_to_search_for]
    anonymization_start_date = user_data['rest_post_anonymization']['json']['submittedTime']
    anonymization_start_date_utc = date_str_to_utc_str(anonymization_start_date)
    log.debug("anonymization_start_date: local {}, UTC {}".format(anonymization_start_date,
                                                                  anonymization_start_date_utc))

    rel_url = '/rest/auditing/1.0/events'
    url = g_config['jira_base_url'] + rel_url
    # URL-parameters:
    # Include the from-date, to not include e.g. previous renamings which has nothing to do with the anonymization,
    # and to limit the amount of response-data. The date must be given in UTC with format "2020-12-30T13:53:17.996Z".
    # The response-JSON is sorted by date descending.
    url_params = {'from': anonymization_start_date_utc}

    user_data['rest_auditing'] = {'doc': "The date in the URL-param is UTC."}
    user_data['rest_auditing'].update({'entries_after_seconds_msg': ''})

    # Jira writes the audit log entries asynchronously. It is unclear how long this takes. Try immediately after
    # the anonymization to read team. If the count of audit logs is 0, wait the seconds goven as list in the
    # following for-loop.
    overall_interval = 0
    intervals = [1, 2, 3, 5]
    # To suppress: Local variable 'r' might be referenced before assignment.
    r = {}
    audit_entry_count = 0
    for interval in intervals:
        time.sleep(interval)
        overall_interval += interval
        r = g_session.get(url=url, params=url_params)
        r.raise_for_status()
        audit_entry_count = r.json()['pagingInfo']['size']
        message = "Got audit log entries after {} seconds: {}. The intervals are: {}." \
                  "Means: Wait 1s and then check for entries. if 0, wait 2s, then 3s, then 5s, then abort." \
            .format(interval, audit_entry_count, intervals)
        log.info(message + " TODO: This will become a DEBUG level message.")
        user_data['rest_auditing']['entries_after_seconds_msg'] = message
        if audit_entry_count > 0:
            break

    if audit_entry_count > 0:
        user_data['rest_auditing'].update({'request': serialize_response(r)})
        auditing_events = r.json()
    else:
        error_message = "{}: The GET {} didn't return any audit log entry within {} seconds." \
                        " No anonymized user-name/key/display-name could be retrieved." \
            .format(user_name_to_search_for, r.request.url, overall_interval)
        log.error(error_message)
        g_execution['errors'].append(error_message)
        return

    user_data['anonymized_data_from_rest'] = {
        'user_name': None,
        'user_key': None,
        'display_name': None,
        # The description is more for development and documentation, not to extract data in advance.
        'description': None
    }
    anonymized_data = user_data['anonymized_data_from_rest']

    for entity in auditing_events['entities']:

        #
        # Similar to get_anonymized_user_data_from_audit_records()
        #

        if is_anonymized_user_data_complete_for_user(user_name_to_search_for):
            break

        try:
            # actionI18nKey was added in Jira 8.10.
            if entity['type']['actionI18nKey'] == 'jira.auditing.user.anonymized':
                for extra_attribute in entity['extraAttributes']:
                    # In Jira 8.10 the 'nameI18nKey' was added.
                    # In Jira 8.10, 8.11, and 8.12 the key to look for is 'description'.
                    # Starting with Jira 8.13, it is 'jira.auditing.extra.parameters.event.description'
                    # Note, this keys 'description' and 'jira.auditing.extra.parameters.event.description' are
                    # also used in the event with key 'jira.auditing.user.anonymization.started', so that key is
                    # not unique. Therefore the path 'event/type/actionI18nKey' is used to identify the event
                    # of interest.
                    key = extra_attribute['nameI18nKey']
                    if key in ['description', 'jira.auditing.extra.parameters.event.description']:
                        anonymized_data['description'] = extra_attribute['value']
                        # The 'value' is something like:
                        #   "User with username 'jirauser10104' (was: 'user4pre84') and key 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                        # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104', 'user4pre84'.
                        # All given in single quotes.
                        parts = re.findall(r"'(.*?)'", extra_attribute['value'])
                        anonymized_data['user_name'] = parts[0]
                        anonymized_data['user_key'] = parts[2]
                        if user_data['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                            # This is a deleted user. There is no display-name to look for in subsequent logs.
                            break
                        else:
                            continue
        except KeyError:
            pass

        # Not every record has the changesValues, so use try/except.
        try:
            changed_values = entity['changedValues']
        except KeyError:
            continue

        display_name_to_search_for = user_data['rest_get_user__before_anonymization']['json']['displayName']
        for changed_value in changed_values:
            if str(changed_value['to']).lower().startswith('jirauser'):
                # This is the tuple either for the user-name (jirauser12345) or the user-key (JIRAUSER12345).
                continue
            if changed_value['from'] == display_name_to_search_for:
                # Found the tuple with the user-display-name. This could be equal to the user-name. And in
                # Jira < 8.4, the user-name could also be equal to the user-key.
                anonymized_data['display_name'] = changed_value['to']


def get_anonymized_user_data_from_audit_records(user_name_to_search_for):
    user_data = g_users[user_name_to_search_for]
    anonymization_start_date = user_data['rest_post_anonymization']['json']['submittedTime']
    anonymization_start_date_utc = date_str_to_utc_str(anonymization_start_date)
    log.debug("anonymization_start_date: local {}, UTC {}".format(anonymization_start_date,
                                                                  anonymization_start_date_utc))

    rel_url = '/rest/api/2/auditing/record'
    url = g_config['jira_base_url'] + rel_url
    # URL-parameters:
    # Include the from-date, to not include e.g. previous renamings which has nothing to do with the anonymization,
    # and to limit the amount of response-data. The date must be given in UTC with format "2020-12-30T13:53:17.996Z".
    # The response-JSON is sorted by date descending.
    url_params = {'from': anonymization_start_date_utc}

    user_data['rest_auditing'] = {'doc': "The date in the URL-param is UTC."}
    user_data['rest_auditing'].update({'entries_after_seconds_msg': ''})

    # Jira writes the audit log entries asynchronously. It is unclear how long this takes. Try immediately after
    # the anonymization to read team. If the count of audit logs is 0, wait the seconds goven as list in the
    # following for-loop.
    overall_interval = 0
    intervals = [1, 2, 3, 5]
    # To suppress: Local variable 'r' might be referenced before assignment.
    r = {}
    audit_entry_count = 0
    for interval in intervals:
        time.sleep(interval)
        overall_interval += interval
        r = g_session.get(url=url, params=url_params)
        r.raise_for_status()
        audit_entry_count = len(r.json()['records'])
        message = "Got audit log entries after {} seconds: {}. The intervals are: {}." \
                  "Means: Wait 1s and then check for entries. if 0, wait 2s, then 3s, then 5s, then abort." \
            .format(interval, audit_entry_count, intervals)
        log.info(message + " TODO: This will become a DEBUG level message.")
        user_data['rest_auditing']['entries_after_seconds_msg'] = message
        if audit_entry_count > 0:
            break

    if audit_entry_count > 0:
        user_data['rest_auditing'].update({'request': serialize_response(r)})
        auditing_records = r.json()
    else:
        error_message = "{}: The GET {} didn't return any audit log entry within {} seconds." \
                        " No anonymized user-name/key/display-name could be retrieved." \
            .format(user_name_to_search_for, r.request.url, overall_interval)
        log.error(error_message)
        g_execution['errors'].append(error_message)
        return

    user_data['anonymized_data_from_rest'] = {
        'user_name': None,
        'user_key': None,
        'display_name': None,
        # The description is more for development and documentation, not to extract data in advance.
        'description': None
    }
    anonymized_data = user_data['anonymized_data_from_rest']

    for record in auditing_records['records']:
        #
        # About the actions
        #
        # The order of actions after an anonymization is:
        #   1. record.summary: "User anonymization started"
        #   2. record.summary: "User updated"
        #   3. record.summary: "User's key changed"
        #   4. record.summary: "User renamed"
        #   5. record.summary: "User anonymized"
        #
        # The events are sorted by date descending. This means, the above actions come in the order 5 to 1.
        #
        # We're looking here for the new user-name, the new user-key (if the user is pre-Jira-8.4-user), and
        # the new display-name. It is sufficient to look into 'User renamed' and 'User updated' to get these data.
        #
        # Unfortunately, the summaries depend on the system-default-language. So we can't check for them. We
        # have to look in to the changedValues directly.
        #

        if is_anonymized_user_data_complete_for_user(user_name_to_search_for):
            break

        try:
            # Until Jira 8.9.x the summary is always EN and 'User anonymized'. Starting with Jira 8.10, the
            # summary language depends on the system default language. E. g. in DE it is 'Benutzer anonymisiert'.
            # But this API '/rest/api/2/auditing/record' is used by the Anonymizer only for Jira-version before 8.10,
            if record['summary'] == 'User anonymized':
                anonymized_data['description'] = record['description']
                # The 'description' is something like:
                #   "User with username 'jirauser10104' (was: 'user4pre84') and key 'JIRAUSER10104' (was: 'user4pre84') has been anonymized."
                # The parts of interest are 'jirauser10104', 'user4pre84', 'JIRAUSER10104', 'user4pre84'.
                # All given in single quotes.
                parts = re.findall(r"'(.*?)'", record['description'])
                anonymized_data['user_name'] = parts[1]
                anonymized_data['user_key'] = parts[3]
                if user_data['rest_get_user__before_anonymization']['json']['emailAddress'] == '?':
                    # This is a deleted user. There is no display-name to look for in subsequent logs.
                    break
                else:
                    continue
        except KeyError:
            pass

        # Not every record has the changesValues, so use try/except.
        try:
            changed_values = record['changedValues']
        except KeyError:
            continue

        display_name_to_search_for = user_data['rest_get_user__before_anonymization']['json']['displayName']
        for changed_value in changed_values:
            if str(changed_value['changedTo']).lower().startswith('jirauser'):
                # This is the tuple either for the user-name (jirauser12345) or the user-key (JIRAUSER12345).
                continue
            if changed_value['changedFrom'] == display_name_to_search_for:
                # Found the tuple with the user-display-name. This could be equal to the user-name. And in
                # Jira < 8.4, the user-name could also be equal to the user-key.
                anonymized_data['display_name'] = changed_value['changedTo']


def get_anonymized_user_data_from_audit_log(user_name_to_search_for):
    """
    Get the anonymized user-data from the audit-log.

    Use either the audit-records API or the newer audit-events API, depending on the Jira-version.

    :param user_name_to_search_for: The user-name to search for in the audit-log
    :return: None.
    """

    # Atlassian introduced anonymization in Jira 8.7.
    # The Anonymizer queries the anonymized user-data from the audit-log.
    #
    # Jira supports two auditing REST-APIs:
    #
    #   1. GET /rest/api/2/auditing/record, deprecated since 8.12.
    #       https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords
    #   2. "Audit log improvements for developers", introduced in 8.8.
    #       https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html
    #
    # A switch in this function delegates calls to the audit REST-APIs depending on the Jira-version:
    # Until 8.9.x, the API 1) is used. For 8.10 and later, the new API 2) is used.
    #
    # Why is Jira 8.10 the border?
    # The language used in parts of the audit-logs depends on the system default language. This affects
    # attributes. Attributes are an easy way to identify the content the Analyzer shall read. But if
    # attributes occur in different languages, this isn't possible.
    # API 1): Until Jira 8.9.x the summary is always EN and 'User anonymized'. Starting with Jira 8.10, the
    # summary language depends on the system default language. E.g. in DE it is 'Benutzer anonymisiert'.
    # API 2) has i18n-keys. These keys are not consistent across the Jira-versions. But starting with Jira 8.10,
    # they can be used. See get_anonymized_user_data_from_audit_events() for more details.
    #
    # Reading the audit-log user by user, or for all users in one go?
    # Collecting the anonymized user-data could also be done in one go after all users have been
    # anonymized. But that is not as easy as it sounds: Both APIs are limited in output. the API 1) is
    # limited to 1.000 records, and the API 2) is paged with a default of 200 events/page. That could
    # be fiddly. I'm confident there is not really a downside in execution-time if the anonymized
    # data is called for each user one by one.
    if is_jira_version_less_then(8, 10):
        get_anonymized_user_data_from_audit_records(user_name_to_search_for)
    else:
        get_anonymized_user_data_from_audit_events(user_name_to_search_for)


def is_any_anonymization_running():
    log.info("?")
    progress_percentage = get_anonymization_progress()
    # Any value <0 means "not in progress".
    if progress_percentage < 0:
        log.info("No")
        return False
    else:
        log.info("Yes")
        return True


def time_diff(d1, d2):
    format_string = '%Y-%m-%dT%H:%M:%S.%f'
    dd1 = datetime.strptime(d1.split("+")[0], format_string)
    dd2 = datetime.strptime(d2.split("+")[0], format_string)
    return dd2 - dd1


def get_formatted_timediff_mmss(time_diff):
    """Convert the given time_diff to format "MM:SS". If the time-diff is < 1s, overwrite it to 1s.

    The MM can be > 60 min.

    :param time_diff: The time-diff
    :return: Time-diff in MM:SS, but min. 1s.
    """

    # Convert to integer because nobody will be interested in the milliseconds-precision. If the diff is 0,
    # overwrite it to 1 (second).
    s = int(time_diff.total_seconds())
    if s == 0:
        s = 1
    minutes = s // 60
    seconds = s % 60
    formatted_diff = "{:02d}:{:02d}".format(minutes, seconds)

    return formatted_diff


def get_formatted_timediff_hhmmss(time_diff):
    """Convert the given time_diff to format "HH:MM:SS". If the time-diff is < 1s, overwrite it to 1s.

    The HH can be > 24 h.

    :param time_diff: The time-diff
    :return: Time-diff in MM:SS, but min. 1s.
    """

    # Convert to integer because nobody will be interested in the milliseconds-precision. If the diff is 0,
    # overwrite it to 1 (second).
    s = int(time_diff.total_seconds())
    if s == 0:
        s = 1

    hours, remainder = divmod(s, 3600)
    minutes, seconds = divmod(remainder, 60)
    formatted_diff = '{:02d}:{:02d}:{:02d}'.format(hours, minutes, seconds)

    return formatted_diff


def create_raw_report(overall_report):
    """Create a raw-data-report as a basis for some post-processing to render some more pretty reports."""

    report = {
        'overview': None,
        'users': []
    }

    number_of_skipped_users = 0
    number_of_anonymized_users = 0
    users_data = overall_report['users_from_user_list_file']
    for user_name, user_data in users_data.items():

        try:
            user_key = user_data['rest_get_user__before_anonymization']['json']['key']
            user_display_name = user_data['rest_get_user__before_anonymization']['json']['displayName']
            active = user_data['rest_get_user__before_anonymization']['json']['active']
        except KeyError:
            user_key = None
            user_display_name = None
            active = None
        # 'deleted' was added in Jira 8.10.
        try:
            deleted = user_data['rest_get_user__before_anonymization']['json']['deleted']
        except KeyError:
            deleted = None

        try:
            validation_has_errors = len(user_data['rest_get_anonymization__query_validation']['errors']) > 0
        except KeyError:
            validation_has_errors = False

        try:
            user_filter = user_data['user_filter']
            filter_is_anonymize_approval = user_filter['is_anonymize_approval']
            if not filter_is_anonymize_approval:
                number_of_skipped_users += 1
            filter_error_message = user_filter['error_message']
        except KeyError:
            # TODO Something went wrong. Let the user know.
            filter_is_anonymize_approval = None
            filter_error_message = None

        try:
            time_start = user_data['rest_get_anonymization_progress']['json']['startTime']
            time_finish = user_data['rest_get_anonymization_progress']['json']['finishTime']
            is_anonymized = user_data['rest_get_anonymization_progress']['status_code'] == 200 and \
                            user_data['rest_get_anonymization_progress']['json']['status'] == 'COMPLETED'
        except KeyError:
            time_start = None
            time_finish = None
            is_anonymized = False

        if is_anonymized:
            number_of_anonymized_users += 1
            diff = time_diff(time_start, time_finish)
            # After the diff is calculated, cut off the milliseconds and DST. They are useless for the user.
            time_start = time_start.split(".")[0]
            time_finish = time_finish.split(".")[0]
        else:
            diff = None

        user_report = {
            'user_name': user_name,
            'user_key': user_key,
            'user_display_name': user_display_name,
            'active': active,
            'deleted': deleted,
            'validation_has_errors': validation_has_errors,
            'filter_is_anonymize_approval': filter_is_anonymize_approval,
            'filter_error_message': filter_error_message,
            'time_start': time_start,
            'time_finish': time_finish,
            'time_duration': '{}'.format(get_formatted_timediff_mmss(diff)) if diff is not None else None
        }

        anonymized_user_name = None
        anonymized_user_key = None
        anonymized_user_display_name = None
        if is_anonymized:
            try:
                anonymized_user_name = user_data['anonymized_data_from_rest']['user_name']
                anonymized_user_key = user_data['anonymized_data_from_rest']['user_key']
                anonymized_user_display_name = user_data['anonymized_data_from_rest']['display_name']
            except KeyError:
                pass
            # The anonymized_user_display_name is not checked here: For deleted users, there is no display-name,
            # the anonymized_user_display_name is None, it is likely this is a deleted user rather than a
            # tool-error.
            if not anonymized_user_name or not anonymized_user_key:
                # This function create_raw_report() is called twice. Put each error only once into the error-list.
                error = "Anonymization data for user {} is incomplete".format(user_name)
                if error not in g_execution['errors']:
                    g_execution['errors'].append("Anonymization data for user {} is incomplete".format(user_name))

        user_report['anonymized_user_name'] = anonymized_user_name
        user_report['anonymized_user_key'] = anonymized_user_key
        user_report['anonymized_user_display_name'] = anonymized_user_display_name

        if is_anonymized:
            user_report['action'] = 'anonymized'
        else:
            user_report['action'] = 'skipped'

        report["users"].append(user_report)

    report['overview'] = {
        'number_of_users_in_user_list_file': len(users_data),
        'number_of_skipped_users': number_of_skipped_users,
        'number_of_anonymized_users': number_of_anonymized_users,
        'is_background_reindex_triggered': False
    }
    return report


def write_result_to_console(overview):
    print("Anonymizing Result:")
    print("  Users in user-list-file:  {}".format(overview['number_of_users_in_user_list_file']))
    print("  Skipped users:            {}".format(overview['number_of_skipped_users']))
    print("  Anonymized users:         {}".format(overview['number_of_anonymized_users']))
    print("  Background re-index triggered:  {}".format(overview['is_background_reindex_triggered']))
    print("")

    if len(g_execution['errors']) > 0:
        print("Errors have occurred during execution:\n  {}\n".format('\n  '.join(g_execution['errors'])))


def trigger_reindex():
    """Trigger a background reindex.

    Note,
    from https://confluence.atlassian.com/jirakb/reindex-jira-server-using-rest-api-via-curl-command-663617587.html:

    "For JIRA DC a better approach than background indexing is to take one node out of the cluster and run
    FOREGROUND reindexing.
    See  JRASERVER-66969 - Discourage Background Indexing for Datacenter instances in Indexing Page CLOSED"
    """

    # Also from
    # https://confluence.atlassian.com/jirakb/reindex-jira-server-using-rest-api-via-curl-command-663617587.html:
    #   - FOREGROUND - runs a lock/full reindexing
    #   - BACKGROUND - runs a background reindexing. If JIRA fails to finish the background reindexing, respond
    #       with 409 Conflict (error message).
    #   - BACKGROUND_PREFERRED  - If possible do a background reindexing. If it's not possible (due to an inconsistent
    #       index), do a foreground reindexing.
    url_params = {
        'type': 'BACKGROUND',
        'indexComments': True,
        'indexChangeHistory': True,
        'indexWorklogs': True
    }
    rel_url = '/rest/api/2/reindex?' + parse.urlencode(url_params)
    url = g_config['jira_base_url'] + rel_url
    r = g_session.post(url=url)
    g_execution['rest_post_reindex'] = serialize_response(r)


def to_date_string(date_time: datetime):
    """Create a uniform date/time-string without nit-picky milliseconds"""
    return date_time.strftime('%Y-%m-%dT%H:%M:%S')


def now_to_date_string():
    return to_date_string(datetime.now())


def create_report_dir():
    if g_config['report_out_dir'] == '.':
        return pathlib.Path(g_config['report_out_dir'])
    else:
        report_dirpath = pathlib.Path(g_config['report_out_dir'])
        report_dirpath.mkdir(parents=True, exist_ok=True)
        return report_dirpath


def at_exit_complete_and_write_details_report():
    log.debug("")

    try:
        # Check if finished-date is present. If not, the script was aborted.
        g_details['execution']['script_finished']
    except KeyError:
        g_details['execution']['script_finished'] = now_to_date_string()
        g_details['execution']['is_script_aborted'] = True
        log.warning("Script has been aborted.")

    report_dirpath = create_report_dir()
    file_path = report_dirpath.joinpath(g_config['report_details_filename'])
    log.debug("  file_path for report_details_filename is {}".format(file_path))
    with open(file_path, 'w') as f:
        print("{}".format(json.dumps(get_sanitized_global_details(), indent=4, ensure_ascii=False)), file=f)


def at_exit_write_anonymization_reports():
    log.debug("")

    try:
        # Check if finished-date is present. If not, the script has been aborted.
        g_details['execution']['script_finished']
    except KeyError:
        g_details['execution']['script_finished'] = now_to_date_string()
        g_details['execution']['is_script_aborted'] = True
        log.warning("Script has been aborted.")

    raw_report = create_raw_report(g_details)
    g_details['execution']['script_execution_time'] = get_formatted_timediff_hhmmss(
        time_diff(
            g_details['execution']['script_started'] + '.000',
            g_details['execution']['script_finished'] + '.000'))

    report_dirpath = create_report_dir()
    file_path = report_dirpath.joinpath(g_config['report_json_filename'])
    log.debug("  file_path for report_json_filename is {}".format(file_path))
    with open(file_path, 'w') as f:
        print("{}".format(json.dumps(raw_report, indent=4)), file=f)

    file_path = pathlib.Path(g_config['report_out_dir']).joinpath(g_config['report_text_filename'])
    log.debug("  file_path for report_text_filename is {}".format(file_path))
    with open(file_path, 'w', newline='') as f:
        fieldnames = ['user_name', 'user_key', 'user_display_name', 'active', 'deleted',
                      'validation_has_errors',
                      'filter_is_anonymize_approval', 'filter_error_message',
                      'action',
                      'time_start', 'time_finish', 'time_duration',
                      'anonymized_user_name', 'anonymized_user_key', 'anonymized_user_display_name']

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(raw_report['users'])

    write_result_to_console(raw_report['overview'])


def get_inactive_users(excluded_users):
    """Query inactive users and filter-out users from the excluded_users and
    the already anonymized users.

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

    This function uses the REST API `/rest/api/2/user/search`. There is a open Jira-bug documented
    in [JRASERVER-29069](https://jira.atlassian.com/browse/JRASERVER-29069) which leads (in some
    Jira instances) to a max. of 1000 users. I have seen this bug in some instances, but others
    delivered more than 1000 users as expected.

    If the number or returned users is exact 1000, it is likely you ran into the bug.

    :return: Users.
    """

    excluded_user_names = excluded_users.keys()
    log.debug(" Excluded users: {}".format(excluded_user_names))

    rel_url = '/rest/api/2/user/search'
    log.debug("")
    is_beyond_last_page = False
    url = g_config['jira_base_url'] + rel_url
    start_at = 0
    user_count_so_far = 0
    users = {}
    # Query the paged API until an empty page.
    while not is_beyond_last_page:
        url_params = {
            'username': '.',
            'includeActive': False,
            'includeInactive': True,
            # 'maxResults': max_results,
            'startAt': start_at}
        r = g_session.get(url=url, params=url_params)
        log.debug("{}".format(serialize_response(r, False)))
        r.raise_for_status()
        user_count_so_far += len(r.json())
        if len(r.json()) == 0:
            is_beyond_last_page = True
            # Warning about JRASERVER-29069.
            if user_count_so_far == 1000:
                log.warning(
                    "The REST API '{}' returned exact 1000 users."
                    " This could mean you ran into JRASERVER-29069."
                    " In that case there could be more inactive users".format(rel_url))
            continue
        start_at += len(r.json())

        for user in r.json():
            user_name = str(user['name'])
            email_address = user['emailAddress']
            if user_name in excluded_user_names or email_address.find('@jira.invalid') >= 0:
                continue
            users.update({
                user_name: {
                    'name': user['name'],
                    'key': user['key'],
                    'display_name': user['displayName'],
                    'email_address': user['emailAddress']
                }
            })
    return users


def check_if_groups_exist(group_names):
    rel_url = '/rest/api/2/group/member'
    log.debug("{}".format(group_names))
    url = g_config['jira_base_url'] + rel_url
    errors = []
    for group_name in group_names:
        url_params = {'groupname': group_name}
        r = g_session.get(url=url, params=url_params)
        if r.status_code == 404:
            errors.append(', '.join(r.json()['errorMessages']))
        else:
            r.raise_for_status()
    return errors


def get_users_from_group(group_name):
    rel_url = '/rest/api/2/group/member'
    log.debug("{}".format(group_name))
    is_last_page = False
    url = g_config['jira_base_url'] + rel_url
    start_at = 0
    users = {}
    while not is_last_page:
        url_params = {'groupname': group_name, 'includeInactiveUsers': True, 'startAt': start_at}
        r = g_session.get(url=url, params=url_params)
        r.raise_for_status()
        for user in r.json()['values']:
            users.update({
                user['name']: {
                    'name': user['name'],
                    'key': user['key'],
                    'display_name': user['displayName'],
                    'email_address': user['emailAddress']
                }
            })
        is_last_page = r.json()['isLast']
        start_at += r.json()['maxResults']
    return users


def get_users_from_groups(group_names):
    log.debug(" {}".format(group_names))
    excluded_users = {}
    for group_name in group_names:
        excluded_users.update(get_users_from_group(group_name))
    return excluded_users


def subcommand_inactive_users():
    try:
        # exclude_groups could be absent.
        excluded_users = get_users_from_groups(g_config['exclude_groups'])
        g_details['excluded_users'] = excluded_users
    except KeyError:
        excluded_users = {}

    remaining_inactive_users = get_inactive_users(excluded_users)
    g_details['remaining_inactive_users'] = remaining_inactive_users

    report_dirpath = create_report_dir()
    file_path = report_dirpath.joinpath(INACTIVE_USERS_OUTFILE)
    with open(file_path, 'w') as f:
        print("# File generated at {}".format(now_to_date_string()), file=f)
        print("# Users: {}".format(len(remaining_inactive_users)), file=f)
        print("# User attributes: User-name; user-key; display-name; email-address\n", file=f)
        for user_name, user_data in remaining_inactive_users.items():
            print("# {}; {}; {}; {}"
                  .format(user_data['name'], user_data['key'], user_data['display_name'], user_data['email_address']),
                  file=f)
            print("{}\n".format(user_data['name']), file=f)


def cleanup():
    g_session.close()


def main():
    g_details['execution']['script_started'] = now_to_date_string()
    g_execution['errors'] = []
    args = parse_parameters()

    if args.subparser_name in [CMD_ANONYMIZE, CMD_VALIDATE]:
        # => Let at_exit_...() write the reports.
        atexit.register(cleanup)
        atexit.register(at_exit_complete_and_write_details_report)
        atexit.register(at_exit_write_anonymization_reports)
        log.debug("")
        read_users_from_user_list_file()

        log.debug("")
        get_users_data(g_users)

        log.debug("")
        get_anonymization_validation_data(g_users)

        log.debug("")
        filter_users(g_users)

        if args.subparser_name == CMD_ANONYMIZE:
            log.debug("")
            if is_any_anonymization_running():
                log.error("There is an anonymization running, or the status of anonymization couldn't be read."
                          " In both cases this script must not continue because these cases are not handled."
                          " Exiting.")
                sys.exit(2)
            log.debug("")
            users_to_be_anonymized = {user_name: user_data for (user_name, user_data) in g_users.items() if
                                      user_data['user_filter']['is_anonymize_approval'] is True}
            if not g_config['is_dry_run']:
                # run_user_anonymization() expects the user-key, not the user-name.
                new_owner_key = g_execution['rest_get_user__new_owner']['json']['key']
                anonymize_users(users_to_be_anonymized, new_owner_key)

        # Re-indexing is specific to the 'anonymize'-command. The re-index shall only be triggered
        # if there is at least one anonymized user. Only the report provides information about the
        # number of anonymized users, so we have to create the report fist.
        raw_report = create_raw_report(g_details)
        if raw_report['overview']['number_of_anonymized_users'] > 0 and g_config['is_trigger_background_reindex']:
            # Let the user know if a re-index has been triggered.
            # The following attribute 'is_background_reindex_triggered' is not the parameter
            # 'is_trigger_background_reindex' got from the command-line.
            # The Anonymizer uses two different parameters because a re-index is only triggered if at least
            # one user was anonymized
            raw_report['overview']['is_background_reindex_triggered'] = True
            trigger_reindex()

        g_details['execution']['script_finished'] = now_to_date_string()
        g_details['execution']['is_script_aborted'] = False

    elif args.subparser_name == CMD_INACTIVE_USERS:
        # => Let at_exit_...() write the reports.
        atexit.register(at_exit_complete_and_write_details_report)
        subcommand_inactive_users()
        g_details['execution']['script_finished'] = now_to_date_string()
        g_details['execution']['is_script_aborted'] = False


if __name__ == '__main__':
    main()

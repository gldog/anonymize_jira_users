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

CMD_ANONYMIZE = 'anonymize'
# The validate-command is a subset of the anonymize-command. They share a lot of code and the "anonymization"-reports.
CMD_VALIDATE = 'validate'
CMD_MISC = 'misc'
CMD_INACTIVE_USERS = 'inactive-users'

DEFAULT_CONFIG = {
    'jira_base_url': '',
    'jira_auth': '',
    'user_list_file': '',
    # Force a character-encoding for reading the user_list_file. Empty means platform dependent Python suggests.
    'encoding': None,
    'report_out_dir': '.',
    'loglevel': 'INFO',
    'is_expand_validation_with_affected_entities': False,
    'is_dry_run': False,
    # The user-name of the new owner.
    'new_owner': '',
    # Delay between a scheduled anonymization and starting querying the progress. Jira's setting is 10s.
    'initial_delay': 10,
    # Interval between progress-queries. Jira's setting is 3s
    'regular_delay': 3,
    # Time in seconds the anonymization shall wait to be finished.
    # 0 (or any negative value) means: Wait as long as it takes.
    'timeout': 0,
    'is_do_background_reindex': False,
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

g_config = DEFAULT_CONFIG

# The keys are:
#   - script_started
#   - rest_get_mypermissions
#   - rest_get_	user__new_owner
#   - rest_get_anonymization_progress__before_anonymization
#   - rest_auditing_events
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
    if sanitized_details['effective_config']['jira_auth']:
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


def is_jira_version_8_7():
    return str(g_execution['rest_get_serverInfo']['json']['version']).startswith('8.7.')


def write_default_cfg_file(config_template_filename):
    with open(config_template_filename, 'w') as f:
        help_text = """        ####
        #
        # Configuration for {scriptname}
        #
        # General:
        #
        #   - This configuration was generated with command line option -g. The parameters
        #       listed in this file are all the ones you can set and are more than you can
        #       set by command line options. If parameters have a value, these are the
        #       Anonymizer's defaults.
        #   - Parameters without values are ignored, but must have a '='.
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
        #   File with user-names to be anonymized or just validated. One user-name per line. 
        #   Comments are allowed: They must be prefixed by '#' and they must appear on their own line.
        #   The character-encoding is platform dependent Python suggests.
        #   If you have trouble with the encoding, try out the parameter '--encoding'.
        #   The given value is an example.
        #user_list_file = usernames.txt
        #   Force a character-encoding for reading the user_list_file. Empty means platform dependent Python suggests.
        #   If you run on Win or the user_list_file was created on Win, try out one of these encodings:
        #     utf-8, cp1252, latin1 
        #   The given value is an example.
        #encoding = utf-8
        #   Output-directory to write the reports into.
        #report_out_dir = {report_out_dir}
        #   Include 'affectedEntities' in the validation result. This is only for documentation 
        #   to enrich the detailed report. It doesn't affect the anonymization.
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
        #   Jira's default is {initial_delay} seconds, and this is also the Anonymizer's default.
        #initial_delay = {initial_delay}
        #   The delay in seconds between calls to get the anonymization-progress.
        #   Jira's default is {regular_delay} seconds, and this is also the Anonymizer's default.
        #regular_delay = {regular_delay}
        #   Time in seconds the anonymization shall wait to be finished.
        #   0 (or any negative value) means: Wait as long as it takes.
        #timeout = {timeout}
        #   If at least one user was anonymized, trigger a background re-index.
        #   The given value is the default.
        #is_do_background_reindex = {is_do_background_reindex}
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
                   is_do_background_reindex=g_config['is_do_background_reindex'])
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
        if v.lower() in BOOLEAN_TRUE_VALUES:
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
        .add_argument('--info', action='store_true',
                      help="Print the effective config, and the character-encoding Python suggests, then exit.")

    #
    # Arguments common to 'anonymize' and 'validate'.
    #
    parent_parser_for_anonymize_and_validate = argparse.ArgumentParser(add_help=False)
    parent_parser_for_anonymize_and_validate \
        .add_argument('-i', '--user-list-file',
                      help="File with user-names to be anonymized or just validated."
                           " One user-name per line. Comments are allowed:"
                           " They must be prefixed by '#' and they must appear on their own line."
                           " The character-encoding is platform dependent Python suggests."
                           " If you have trouble with the encoding, try out the parameter '--encoding'.")
    parent_parser_for_anonymize_and_validate \
        .add_argument('--encoding', metavar='ENCODING',
                      help="Force a character-encoding for reading the user-list-file."
                           " Empty means platform dependent Python suggests."
                           " If you run on Win or the user-list-file was created on Win, try out one of these encodings:"
                           " utf-8, cp1252, latin1.")
    parent_parser_for_anonymize_and_validate \
        .add_argument('--expand-validation-with-affected-entities', default=False,
                      action='store_true',
                      dest='is_expand_validation_with_affected_entities',
                      help="Include 'affectedEntities' in the validation result."
                           " This is only for documentation to enrich the detailed report."
                           " It doesn't affect the anonymization.")

    sp = parser.add_subparsers(dest='subparser_name')
    sp_anonymize = sp.add_parser(CMD_ANONYMIZE,
                                 parents=[parent_parser,
                                          parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                          parent_parser_for_anonymize_and_validate,
                                          parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                 help="Anonymizes users.")
    sp_validate = sp.add_parser(CMD_VALIDATE,
                                parents=[parent_parser,
                                         parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                         parent_parser_for_anonymize_and_validate,
                                         parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                help="Validates user anonymization process.")
    sp_misc = sp.add_parser(CMD_MISC, parents=[parent_parser],
                            help="Intended to bundle diverse functions."
                                 " Currently `-g` to generate a template-config-file is the only function.")

    #
    # Add arguments special to command "anonymize".
    #
    sp_anonymize.add_argument('-D', '--dry-run', action='store_true',
                              help="Finally do not anonymize."
                                   " To get familiar with the script and to test it.")
    sp_anonymize.add_argument('-n', '--new-owner',
                              help="Transfer roles of all anonymized users to the user with this user-name.")
    sp_anonymize.add_argument('-x', '--background-reindex', action='store_true',
                              dest='is_do_background_reindex',
                              help="If at least one user was anonymized, trigger a background re-index.")

    #
    # Add arguments special to command "misc".
    #
    sp_misc.add_argument('-g', '--generate-config-template', metavar='CONFIG_TEMPLATE_FILE',
                         const=TEMPLATE_FILENAME, nargs='?',
                         dest='config_template_filename',
                         help="Generate a configuration-template. Defaults to {}.".format(
                             TEMPLATE_FILENAME))

    #
    # Add arguments special to command "inactive-users".
    #
    sp_inactive_users = sp.add_parser(CMD_INACTIVE_USERS,
                                      parents=[parent_parser,
                                               parent_parser_for_anonymize_and_inactiveusers_and_validate,
                                               parent_parser_for_anonymize_and_inactiveusers_and_validate_post],
                                      help="Retrieves a list of inactive, not-yet anonymized users."
                                           " These users are candidates for anonymization.")
    sp_inactive_users.add_argument('--exclude-groups', nargs='+',
                                   help="Exclude members of these groups.")

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

    errors = []
    #
    # Checks for 'anonymize', 'inactive-users', and 'validate'.
    #
    if args.subparser_name in [CMD_ANONYMIZE, CMD_INACTIVE_USERS, CMD_VALIDATE]:
        if args.info:
            gd = get_sanitized_global_details()
            print("  Effective config: {}".format(json.dumps(gd['effective_config'], indent=4)))
            print("  getpreferredencoding {}, getfilesystemencoding {}".format(locale.getpreferredencoding(),
                                                                               sys.getfilesystemencoding()))
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
            r = get_user_data(g_config['new_owner'])
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


def get_user_data(user_name):
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


def get_validation_data(users):
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
    log.info("by existence and validation-data")

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

    log.debug("progress_percentage {}".format(progress_percentage))

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
            log.info("Progress {}".format(progress_percentage))
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
                # Atlassian introduced anonymization in Jira 8.7.
                # We query the anonymized user-data from the audit-log.
                # Jira supports two auditing REST-APIs:
                #   1. GET /rest/api/2/auditing/record, deprecated since 8.12.
                #       https://docs.atlassian.com/software/jira/docs/api/REST/8.0.0/#api/2/auditing-getRecords
                #   2. "Audit log improvements for developers", introduced in 8.8.
                #       https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html
                # The following switch delegates calls the audit REST-API depending on the Jira-version:
                # For 8.7, the previous API 1) is used. For 8.8 and later, the new API 2) is used.
                # For pre-8.7 it doesn't care as that versions do not support anonymization.
                #
                # Collecting the anonymized user-data is done before handling the timeout to save what still can
                # be saved.
                #
                # Collecting the anonymized user-data could also be done in one go after all users have been
                # anonymized. But that is not as easy as it sounds: Both APIs are limited in output. the API 1) is
                # limited to 1.000 records, and the API 2) is paged with a default of 200 events/page. That could
                # be fiddly. I'm confident there is not really a downside in execution-time if the anonymized
                # data is called for each user one by one.
                if is_jira_version_8_7():
                    get_anonymized_user_data_from_audit_records(user_name)
                else:
                    get_anonymized_user_data_from_audit_events(user_name)
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


def is_anonymized_user_data_complete_for_user(user_name, key):
    """Check if all three items user-name, -key, and display-name are collected so far.
     If so, we're done with this user.
     """

    anonymized_data = g_users[user_name][key]
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
    r = g_session.get(url=url, params=url_params)
    user_data['rest_auditing_events'] = {'doc': "The date in the URL-param is UTC."}
    user_data['rest_auditing_events'].update(serialize_response(r))
    # Expect 200 OK here.
    r.raise_for_status()
    auditing_events = r.json()

    anonymized_data_key = 'anonymized_data_from_rest'

    user_data[anonymized_data_key] = {
        'user_name': None,
        'user_key': None,
        'display_name': None
    }

    for entity in auditing_events['entities']:
        # try: This is a very defensive implementation. I'm not that experienced with the auditing-API.
        # Maybe there is not a type.action in every entity.
        try:
            action = entity['type']['action']
        except KeyError:
            continue

        #
        # About the actions
        #
        # The order of actions after an anonymization is:
        #   1. entity.type.action: "User anonymization started"
        #   2. entity.type.action: "User updated";
        #       changedValues: "Email" ..., "Full name" from "User 1 Pre 84" to "user-2127b"
        #   3. entity.type.action: "User's key changed"; changedValues: "Key" from "user1pre84" to "JIRAUSER10104"
        #   4. entity.type.action: "User renamed"; changedValues: "Username" from "user1pre84" to "jirauser10104"
        #   5. entity.type.action: "User anonymized"; changedValues: []
        #
        # The events are sorted by date descending. This means, the above actions come in the order 5 to 1.
        #
        # We're looking here for the new user-name, the new user-key (if the user is pre-Jira-8.4-user), and
        # the new display-name. It is sufficient to hook into 'User renamed' and 'User updated' to get these data.
        #

        if action == 'User renamed':
            # Expect only one list-item here, but for sure iterate over it.
            for changedValue in entity['changedValues']:
                if changedValue['key'] == 'Username':
                    from_name_from_audit_log = changedValue['from']
                    if from_name_from_audit_log != user_name_to_search_for \
                            or is_anonymized_user_data_complete_for_user(user_name_to_search_for, anonymized_data_key):
                        break
                    g_users[user_name_to_search_for][anonymized_data_key]['user_name'] = changedValue['to']
                    g_users[user_name_to_search_for][anonymized_data_key]['user_key'] = \
                        entity['affectedObjects'][0]['id']
        elif action == 'User updated':
            # Saw a list with 1 dict, with a 'name' key. I think it is save to access by [0].
            user_name_from_audit_log = entity['affectedObjects'][0]['name']
            if user_name_from_audit_log != user_name_to_search_for \
                    or is_anonymized_user_data_complete_for_user(user_name_to_search_for, anonymized_data_key):
                continue
            for changedValue in entity['changedValues']:
                # I think this list has only one entry: the 'Key'. But technically it is a list, so we should
                # iterate over it.
                # Just for the records: If the user was an active user, one separate event is to set
                # changedValue['key']: "Active / Inactive" "from": "Active" "to": "Inactive".
                if changedValue['key'] == 'Full name':
                    g_users[user_name_to_search_for][anonymized_data_key]['display_name'] = changedValue['to']


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
    # url_params = {} -- for testing
    r = g_session.get(url=url, params=url_params)
    user_data['rest_auditing_records'] = {'doc': "The date in the URL-param is UTC."}
    user_data['rest_auditing_records'].update(serialize_response(r))
    # Expect 200 OK here.
    r.raise_for_status()
    auditing_records = r.json()

    anonymized_data_key = 'anonymized_data_from_rest'
    user_data[anonymized_data_key] = {
        'user_name': None,
        'user_key': None,
        'display_name': None
    }

    for record in auditing_records['records']:
        # try: This is a very defensive implementation. I'm not that experienced with the auditing-API.
        # Maybe there is not a type.summary in every record.
        try:
            summary = record['summary']
        except KeyError:
            continue

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
        # the new display-name. It is sufficient to hook into 'User renamed' and 'User updated' to get these data.
        #

        if summary == 'User renamed':
            # Expect only one list-item here, but for sure I iterate over it.
            for changedValue in record['changedValues']:
                # TODO comment about list
                if changedValue['fieldName'] == 'Username':
                    from_name_from_audit_log = changedValue['changedFrom']
                    if from_name_from_audit_log != user_name_to_search_for \
                            or is_anonymized_user_data_complete_for_user(user_name_to_search_for,
                                                                         anonymized_data_key):
                        break
                    g_users[from_name_from_audit_log][anonymized_data_key]['user_name'] = changedValue['changedTo']
                    g_users[from_name_from_audit_log][anonymized_data_key]['user_key'] = record['objectItem']['id']
        elif summary == 'User updated':
            # Saw a list with 1 dict, with a 'name' key. I think it is save to access by [0].
            user_name_from_record = record['objectItem']['name']
            if user_name_from_record != user_name_to_search_for \
                    or is_anonymized_user_data_complete_for_user(user_name_to_search_for, anonymized_data_key):
                continue
            for changedValue in record['changedValues']:
                # I think this list has only one entry: the 'Key'. But technically it is a list, so we should
                # iterate over it.
                if changedValue['fieldName'] == 'Full name':
                    g_users[user_name_to_search_for][anonymized_data_key]['display_name'] = changedValue['changedTo']


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
            'validation_has_errors': validation_has_errors,
            'filter_is_anonymize_approval': filter_is_anonymize_approval,
            'filter_error_message': filter_error_message,
            'time_start': time_start,
            'time_finish': time_finish,
            'time_duration': '{}'.format(get_formatted_timediff_mmss(diff)) if diff is not None else None
        }

        if is_anonymized:
            try:
                anonymized_user_name = user_data['anonymized_data_from_rest']['user_name']
                anonymized_user_key = user_data['anonymized_data_from_rest']['user_key']
                anonymized_user_display_name = user_data['anonymized_data_from_rest']['display_name']
            except KeyError:
                # This is an error! Let the user know.
                assert False, "Can't read anonymized user-data from 'anonymized_data_from_rest'"
        else:
            anonymized_user_name = ""
            anonymized_user_key = ""
            anonymized_user_display_name = ""

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
        # There is one more attribute: is_background_reindex_triggered. This will be set later just before triggering
        # a re-index. But for printing the report, this attribute has to be present. Set it to False as the default.
        'is_background_reindex_triggered': False
    }
    return report


def write_result_to_stdout(overview):
    print("Anonymizing Result:")
    print("  Users in user-list-file:  {}".format(overview['number_of_users_in_user_list_file']))
    print("  Skipped users:            {}".format(overview['number_of_skipped_users']))
    print("  Anonymized users:         {}".format(overview['number_of_anonymized_users']))
    print("  Background re-index triggered:  {}".format(overview['is_background_reindex_triggered']))
    print("")


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
        print("{}".format(json.dumps(get_sanitized_global_details(), indent=4)), file=f)


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
        fieldnames = ['user_name', 'user_key', 'user_display_name', 'active',
                      'validation_has_errors',
                      'filter_is_anonymize_approval', 'filter_error_message',
                      'action',
                      'time_start', 'time_finish', 'time_duration',
                      'anonymized_user_name', 'anonymized_user_key', 'anonymized_user_display_name']

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(raw_report['users'])

    write_result_to_stdout(raw_report['overview'])


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


def main():
    g_details['execution']['script_started'] = now_to_date_string()
    args = parse_parameters()

    if args.subparser_name in [CMD_ANONYMIZE, CMD_VALIDATE]:
        # => Let at_exit_...() write the reports.
        atexit.register(at_exit_complete_and_write_details_report)
        atexit.register(at_exit_write_anonymization_reports)
        log.debug("")
        read_users_from_user_list_file()

        log.debug("")
        get_users_data(g_users)

        log.debug("")
        get_validation_data(g_users)

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
            if not g_config['dry_run']:
                # run_user_anonymization() expects the user-key, not the user-name.
                new_owner_key = g_execution['rest_get_user__new_owner']['json']['key']
                anonymize_users(users_to_be_anonymized, new_owner_key)

        # Re-indexing is specific to the 'anonymize'-command. The re-index shall only be triggered
        # if there is at least one anonymized user. Only the report provides information about the
        # number of anonymized users, so we have to create the report fist.
        raw_report = create_raw_report(g_details)
        if raw_report['overview']['number_of_anonymized_users'] > 0 and args.is_do_background_reindex:
            # Let the user know if a re-index has been triggered.
            # The following attribute 'is_background_reindex_triggered' is not the parameter
            # 'is_do_background_reindex' got from the command-line.
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

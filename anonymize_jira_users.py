#!/usr/bin/env python3

# Copyright 2020 Johannes Heger
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
import re
import sys
import textwrap
import time
from datetime import datetime
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

DEFAULT_CONFIG = {
    'jira_base_url': '',
    'jira_auth': '',
    'infile': '',
    'loglevel': 'INFO',
    'is_expand_validation_with_affected_entities': False,
    'is_dry_run': False,
    'is_try_delete_user': False,
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
    # None: The default Python suggests. Do not use an empty string here.
    'encoding': None,
    # None instead of an empty string would also work regarding the program logic.
    # But None is forbidden in ConfigParser, which is used to write a default-config-file.
    # So we have to use the empty string.
    'features': ''
}

DEFAULT_CONFIG_REPORT_BASENAME = 'anonymizing_report'
DEFAULT_CONFIG_TEMPLATE_FILENAME = 'my-blank-default-config.cfg'
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
# Features are some kind of extensions only functional with some configuration outside this script.
#
# Feature FEATURE_DO_REPORT_ANONYMIZED_USER_DATA:
# Prerequisite:
#   The REST-endpint
ANONHELPER_APPLICATIONUSER_URL = '/rest/anonhelper/latest/applicationuser'
#   provided by add-on jira-anonymizinghelper, see https://bitbucket.org/jheger/jira-anonymizinghelper/src/master/
#
# Description:
#
# The anonymization changes a user-name to the format "username12345" and the display-name to the format "user-a2b4e".
# If a user was created in Jira-version <8.4, the user-key mostly is equal to the user-name. In this case,
# the anonymization changes also the user-key to the format "JIRAUSER12345". Users created in Jira >= 8.4 already
# have a user-key of this format. We can see, the ID is the base to form the user-name and -key.
#
# During anonymization, the Jira REST-API do not provide any information about the new user-name, user-key,
# display-name, nor the ID ("12345").
#
# If you have to record a mapping from the un-anonymized user to the anonymized user e. g. for legal department,
# this is not possible out of the box.
#
# This feature
#   - reads the user-ID which is the base for the anonymized user-name and -key,
#       from GET /rest/anonhelper/latest/applicationuser before anonymization,
#   - predicts the new user-names,
#   - query the anonymized users by the predicted user-names after anonymization,
#   - records the anonymized user-name, -key, and display-name in addition.
#
# Check if this REST-endpoint can be reached:
#   curl --insecure -u <user>:<pass> <jira-base-url>/rest/anonhelper/latest/applicationuser?username=<a-username>
#
FEATURE_DO_REPORT_ANONYMIZED_USER_DATA = 'do_report_anonymized_user_data'
FEATURES = [FEATURE_DO_REPORT_ANONYMIZED_USER_DATA]
PRETTY_PRINT_FEATURES = "{}".format(FEATURES).replace('[', '').replace(']', '').replace('\'', '')

#
# Global vars.
#

log = logging.getLogger()

g_config = DEFAULT_CONFIG

# The keys are:
#   - rest_get_mypermissions
#   - rest_get_applicationuser__check_if_api_do_respond
#   - rest_get_anonymization_progress__before_anonymization
#   - rest_post_reindex
g_execution = {}

# The user data.
#   - key: user-name
#   - value:
#       - rest_get_user__before_anonymization
#       - rest_get_anonymization__query_validation
#       - user_filter
#           - error_message
#           - is_anonymize_approval
#       - rest_delete_user
#       - rest_post_anonymization
#       - rest_get_anonymization_progress
#       - rest_get_user__query_anonymized_user
g_users = {
    # 'doc': 'This is for collecting user-related data during execution.'
}

# The collected data. This is something like an internal trace-log.
# The reports will be generated from this.
# The keys are:
#   - effective_config
#   - execution: Information about script-execution not specific to users.
#   - users_from_infile: Details about users.
g_details = {
    'effective_config': g_config,
    'execution': g_execution,
    'users_from_infile': g_users
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


def is_feature_do_report_anonymized_user_data_enabled():
    return g_config['features'] and FEATURE_DO_REPORT_ANONYMIZED_USER_DATA in g_config['features']


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


def check_if_feature_do_report_anonymized_user_data_is_functional(user):
    """Check if REST-endpoint for this feature can be reached.
    :return: None if functional. Otherwise an error-message.
    """
    rel_url = ANONHELPER_APPLICATIONUSER_URL
    url = g_config['jira_base_url'] + rel_url
    url_params = {'username': user}
    r = g_session.get(url=url, params=url_params)
    g_execution['rest_get_applicationuser__check_if_api_do_respond'] = serialize_response(r)
    error_message = None
    # In case the URL can't be reached the auth-methodes' results differ:
    #   - With Basic, the status-code is 404. Easy to detect.
    #   - With Bearer, Jira redirects to the Login-page and the status-code is 200! In the first place 200 sounds like
    #       the original request succeeded. But in fact it hasn't.
    #       There are several ways to detect a redirect.
    #           - The length of r.history() is greater than 0. The (in this case single) entry has status-code 302.
    #           - In r.text() is not the JSON-structure we expect (not a JSON at all).
    #           - In r.url() something like "login.jsp" is present.
    #       I'm not confident in this, but I think taking the history into account is the most proper solution.
    if r.status_code == 404:
        error_message = True
    elif r.status_code == 200:
        if len(r.history) > 0:
            # Ran into the redirect (or at least any unexpected behaviour).
            error_message = True
        try:
            # Check if this is the JSON we expect here.
            r.json()[g_config['new_owner']]
        except (KeyError, JSONDecodeError):
            error_message = True

    if error_message:
        error_message = "The URL {} {} needed by feature {} can't be reached.".format(
            r.request.method, ANONHELPER_APPLICATIONUSER_URL, FEATURE_DO_REPORT_ANONYMIZED_USER_DATA)

    return error_message


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
        #   If you have trouble with the encoding, try out the parameter '--encoding'.")
        #   The given value is an example.
        #infile = usernames.txt
        #   Force a character-encoding for reading the infile. Empty means platform dependent Python suggests.
        #   The given value is an example.
        #encoding = utf-8
        #   Include 'affectedEntities' in the validation result. This is only for documentation 
        #   to enrich the detailed report. It doesn't affect the anonymization.
        #   The given value is the default.
        #is_expand_validation_with_affected_entities = {is_expand_validation_with_affected_entities}
        #   Finally do not anonymize. To get familiar with the script and to test it.
        #   The given value is the default.
        #is_dry_run = {is_dry_run}
        #   Try deleting the user. If not possible, do anonymize.
        #   The given value is the default.
        #is_try_delete_user = {is_try_delete_user}
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
        #   Needs an add-on. Valid values are: {features}
        #   Please read the docs about features.
        #features = 
        """.format(scriptname=os.path.basename(__file__),
                   boolean_true=BOOLEAN_TRUE_VALUES,
                   boolean_false=BOOLEAN_FALSE_VALUES,
                   valid_loglevels=PRETTY_PRINT_LOG_LEVELS,
                   loglevel=g_config['loglevel'],
                   is_expand_validation_with_affected_entities=
                                       g_config['is_expand_validation_with_affected_entities'],
                   is_dry_run=g_config['is_dry_run'],
                   is_try_delete_user=g_config['is_try_delete_user'],
                   initial_delay=g_config['initial_delay'],
                   regular_delay=g_config['regular_delay'],
                   timeout=g_config['timeout'],
                   is_do_background_reindex=g_config['is_do_background_reindex'],
                   features=PRETTY_PRINT_FEATURES)
        f.write(textwrap.dedent(help_text))


def read_configfile_and_merge_into_global_config(args):
    """Read the config-file and merge it into the gobal defaults-dict.

    The values within a ConfigParser are always strings. After a merge with a Python dict, the expected types could
    be gone. E.g. if a boolean is expected, but the ConfigParser delivers the string "false", this string is
    True.
    This function additionally converts all read parameters to Python-types.
    :param args: The arguments got from the command-line.
    :return: Nothing.
    """
    parser = configparser.ConfigParser()
    parser.read(args.config_file)
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
        elif k.lower() == 'features':
            # The ConfigParser doesn't parse lists. We have to convert the delimited feature-string to a list by
            # ourself.
            if v:
                real_dict[k] = re.split(r'[\s,;]+', v)
                # If there is a trailing comma, the resulting list contains an entry with an empty string.
                # The following code removes empty entries:
                real_dict[k] = list(filter(None, real_dict[k]))
            else:
                real_dict[k] = []
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


def parse_parameters():
    #
    # Part 1: Define and parse the arguments.
    #
    epilog = """    How to start
    
    o Create the file usernames.txt with the user-names to be anonymized, one 
      user-name per line.
    o Create a config-file-template:
          anonymize_jira_users.py misc -g
      The file my-blank-default-config.cfg has been created.
    o Rename the file, e.g. to my-config.cfg.
    o In that file, set the attributes jira_base_url; jira_auth with
      format 'Basic admin:admin'; new_owner.
    o Call
          anonymize_jira_users.py validate -c my-config.cfg
      to see what would happen in case of anonymizing.
    o Call
          anonymize_jira_users.py anonymize -c my-config.cfg
      to execute anonyization.
    o Have a look at the report anonymization_report.csv. More details about the
      users are given in anonymization_report_details.csv.
    """
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="The Anonymizer is a Python3-script to help Jira-admins anonymizing Jira-users in bulk.",
                                     epilog=textwrap.dedent(epilog))
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('-l', '--loglevel', choices=LOG_LEVELS,
                               help="Log-level. Defaults to {}.".format(DEFAULT_CONFIG['loglevel']))
    parent_parser.add_argument('-c', '--config-file',
                               help="Config-file to pre-set command-line-options."
                                    " You can generate a config-file-template with option 'miisc -g'."
                                    " There are parameters in the config-file not present on the command line."
                                    " Empty parameters in the config-file are ignored."
                                    " Parameters given on the command line overwrite parameters"
                                    " given in the config-file. ")

    #
    # Add arguments for 'anonymize' and 'validate'.
    #
    parent_parser_for_validate_and_anonymize = argparse.ArgumentParser(add_help=False)
    parent_parser_for_validate_and_anonymize \
        .add_argument('--info', action='store_true',
                      help="Print the effective config, and the character-encoding Python suggests, then exit.")
    parent_parser_for_validate_and_anonymize \
        .add_argument('-b', '--jira-base-url', help="Jira base-URL.")
    parent_parser_for_validate_and_anonymize \
        .add_argument('-u', '--jira-auth', metavar='ADMIN_USER_AUTH',
                      help="Admin user-authentication."
                           " Two auth-types are supported: Basic, and Bearer (starting with Jira 8.14)."
                           " The format for Basic is: 'Basic <user>:<pass>'."
                           " The format for Bearer is: 'Bearer <token>'.")
    parent_parser_for_validate_and_anonymize \
        .add_argument('-i', '--infile',
                      help="File with user-names to be anonymized or just validated."
                           " One user-name per line. Comments are allowed:"
                           " They must be prefixed by '#' and they must appear on their own line."
                           " The character-encoding is platform dependent Python suggests."
                           " If you have trouble with the encoding, try out the parameter '--encoding'.")
    parent_parser_for_validate_and_anonymize \
        .add_argument('--encoding', metavar='ENCODING',
                      help="Force a character-encoding for reading the infile."
                           " Empty means platform dependent Python suggests.")
    parent_parser_for_validate_and_anonymize \
        .add_argument('--expand-validation-with-affected-entities', default=False,
                      action='store_true',
                      dest='is_expand_validation_with_affected_entities',
                      help="Include 'affectedEntities' in the validation result."
                           " This is only for documentation to enrich the detailed report."
                           " It doesn't affect the anonymization.")

    sp = parser.add_subparsers(dest='subparser_name')
    sp_anonymize = sp.add_parser('anonymize', parents=[parent_parser, parent_parser_for_validate_and_anonymize])
    sp_validate = sp.add_parser('validate', parents=[parent_parser, parent_parser_for_validate_and_anonymize])
    sp_misc = sp.add_parser('misc', parents=[parent_parser])

    #
    # Add arguments special to "anonymize".
    #
    sp_anonymize.add_argument('-n', '--new-owner',
                              help="Transfer roles of all anonymized users to the user with this user-name.")
    # Combination of "default" and "action":
    # Imagine default=None is not given, and the user gives parameter -d. Then the arg-parser sets
    # args.is_try_delete_user to true as expected. But if the user omit -d, the arg-parser sets args.is_try_delete_user
    # to false implicitly. This would overwrite the setting from the config-file.
    # Default=None sets args.is_try_delete_user to None if the user omits -d. By this, the script can distinguish
    # between the given or the omitted -d.
    sp_anonymize.add_argument('-d', '--try-delete-user', default=None, action='store_true',
                              dest='is_try_delete_user',
                              help="Try deleting the user. If not possible, do anonymize.")
    # This argument belongs to the "anonymize" and therefore is parsed here in context of sp_anonymize.
    # But in future versions of the anonymizer this could become a more global argument.
    sp_anonymize.add_argument('-f', '--features', nargs='+', metavar='FEATURES', default=None,
                              help="Features need external tools. See the docs. Choices: {}".format(
                                  PRETTY_PRINT_FEATURES))
    sp_anonymize.add_argument('-D', '--dry-run', action='store_true',
                              help="Finally do not delete nor anonymize."
                                   " To get familiar with the script and to test it.")
    sp_anonymize.add_argument('-x', '--background-reindex', action='store_true',
                              dest='is_do_background_reindex',
                              help="If at least one user was anonymized, trigger a background re-index.")

    #
    # Add arguments special to "misc".
    #
    sp_misc.add_argument('-g', '--generate-config-template', metavar='CONFIG_TEMPLATE_FILE',
                         const=DEFAULT_CONFIG_TEMPLATE_FILENAME, nargs='?',
                         dest='config_template_filename',
                         help="Generate a configuration-template. Defaults to {}.".format(
                             DEFAULT_CONFIG_TEMPLATE_FILENAME))
    sp_misc.add_argument('--recreate-report', action='store_true',
                         help="Re-create the reports from the details file. Only for development.")

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

    g_config['report_details_filename'] = DEFAULT_CONFIG_REPORT_BASENAME + '_details.json'
    g_config['report_json_filename'] = DEFAULT_CONFIG_REPORT_BASENAME + '.json'
    g_config['report_text_filename'] = DEFAULT_CONFIG_REPORT_BASENAME + '.csv'

    if args.subparser_name == 'misc':
        if args.config_template_filename:
            write_default_cfg_file(args.config_template_filename)
            sys.exit(0)
        elif args.recreate_report:
            recreate_reports()
            sys.exit(0)
        else:
            sp_misc.error("Command 'misc' needs '-g' or '--recreate-report'")

    # In a config-file is given, merge it into the global config. Non-None-values overwrites the values present so far.
    # Note, a config-file can only be present for the sub-parsers.
    if (args.subparser_name == 'validate' or args.subparser_name == 'anonymize') and args.config_file:
        read_configfile_and_merge_into_global_config(args)

    # Merge command line arguments in and over the global config. Non-None-values overwrites the values present so far.
    merge_dicts(g_config, vars(args))

    # The "features"-feature is not bound to a specific sub-parser, so it is validated here.
    if g_config['features'] and not set(g_config['features']).issubset(FEATURES):
        parser.error('{}'.format(
            "Features contain at least one unsupported feature-name. Supported features are: {}".format(FEATURES)))

    #
    # Checks for both sub-parsers.
    #
    if args.subparser_name == 'validate' or args.subparser_name == 'anonymize':
        if args.info:
            gd = get_sanitized_global_details()
            print("  Effective config: {}".format(json.dumps(gd['effective_config'], indent=4)))
            print("  getpreferredencoding {}, getfilesystemencoding {}".format(locale.getpreferredencoding(),
                                                                               sys.getfilesystemencoding()))
            print("")
            sys.exit(0)

        errors = []
        # Check infile is given does exist.
        if not g_config['infile']:
            errors.append("Missing infile")
        else:
            try:
                open(g_config['infile'])
            except IOError:
                errors.append("Infile {} does not exist or is not accessible".format(g_config['infile']))

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
        if len(errors) > 0:
            parent_parser_for_validate_and_anonymize.error('; '.join(errors))

        #
        # Checks for sub-parser 'anonymize'
        #
        if args.subparser_name == 'anonymize':
            if not g_config['new_owner']:
                sp_anonymize.error("Missing new_owner.")
            else:
                r = get_user_data_from_rest(g_config['new_owner'])
                if r.status_code != 200:
                    if r.status_code == 404:
                        sp_anonymize.error(r.json()['errorMessages'])
                    else:
                        r.raise_for_status()

            if g_config['features'] and 'do_report_anonymized_user_data' in g_config['features']:
                # Take new_owner for this check, as this is the only user we assume it exists.
                # We can't use the admin-user because they could use a Bearer-token (without any user-name).
                error_message = check_if_feature_do_report_anonymized_user_data_is_functional(g_config['new_owner'])
                if error_message:
                    sp_anonymize.error(error_message)

    set_logging()

    gd = get_sanitized_global_details()
    log.debug("Effective config: {}".format(gd['effective_config']))
    log.debug(("getpreferredencoding {}, getfilesystemencoding {}".format(locale.getpreferredencoding(),
                                                                          sys.getfilesystemencoding())))

    return args


def read_user_names_from_infile():
    """Read the Jira user-names from the infile. Skip lines starting with hash '#'.

    :return: None.
    """
    log.info("{}".format(g_config["infile"]))
    with open(g_config["infile"], 'r', encoding=g_config['encoding']) as f:
        infile = f.read()
        lines = re.split('[\n\r]+', infile)
        for line in lines:
            line = line.strip()
            # Skip comment lines.
            if line and not line.startswith('#'):
                user_name = line
                g_users[user_name] = {}
    log.info("  The user-names are ({}): {}".format(len(g_users.keys()), list(g_users.keys())))


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


def get_user_data_from_rest(user_name):
    rel_url = '/rest/api/2/user'
    log.info("for user {}".format(user_name))
    url = g_config['jira_base_url'] + rel_url
    url_params = {'username': user_name}
    r = g_session.get(url=url, params=url_params)
    g_execution['rest_get_user__new_owner'] = serialize_response(r)
    log.debug(g_execution['rest_get_user__new_owner'])
    return r


def get_users_data_from_rest():
    rel_url = '/rest/api/2/user'
    log.info("for {} users".format(len(g_users)))
    url = g_config['jira_base_url'] + rel_url
    for user_name in g_users.keys():
        url_params = {'username': user_name}
        r = g_session.get(url=url, params=url_params)
        g_users[user_name]['rest_get_user__before_anonymization'] = serialize_response(r)
        log.debug(g_users[user_name]['rest_get_user__before_anonymization'])


def get_validation_data_from_rest():
    rel_url = '/rest/api/2/user/anonymization'
    log.info("")
    url = g_config['jira_base_url'] + rel_url
    for user_name, user_data in g_users.items():
        if user_data['rest_get_user__before_anonymization']['status_code'] != 200:
            # The user does not exist. A message about this missing user is logged later on
            # in filter_users()
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


def filter_users():
    log.info("by existence and validation-data")

    for user_name, user_data in g_users.items():
        error_message = ""

        #
        #  Check against data got form GET /rest/api/2/user if the user exists and is inactive
        #
        if user_data['rest_get_user__before_anonymization']['status_code'] != 200:
            error_message = '{}'.format(user_data['rest_get_user__before_anonymization']['json']['errorMessages'][0])
        else:
            # Check if the existing user is an active user:
            is_active_user = user_data['rest_get_user__before_anonymization']['json']['active']
            if is_active_user:
                error_message = "Is an active user."

        #
        #  Check against validation result got from GET rest/api/2/user/anonymization.
        #
        if not error_message:
            # try/except: user_data['rest_get_anonymization__query_validation'] could be absent in case of an invalid user-name.
            try:
                if user_data['rest_get_anonymization__query_validation']['status_code'] != 200:
                    error_message = "HTTP status-code of the REST validation API is not 200. "
                # Despite of an status-code of 200 there could be errors (seen in use case "admin tries to
                # anonymize themself).
                if len(user_data['rest_get_anonymization__query_validation']['json']['errors']) > 0:
                    error_message += "There is at least one validation error message."
            except KeyError:
                pass

        user_data['user_filter'] = {}
        user_data['user_filter']['error_message'] = ""
        if error_message:
            user_data['user_filter']['error_message'] = error_message
            user_data['user_filter']['is_anonymize_approval'] = False
            log.warning("User {}: {}".format(user_name, error_message))
        else:
            user_data['user_filter']['is_anonymize_approval'] = True

    vu = {user_name: user_data for (user_name, user_data) in g_users.items() if
          user_data['user_filter']['is_anonymize_approval'] is True}
    log.info("Remaining users to be anonymized: {}".format(list(vu.keys())))


def get_anonymization_progress(user_name=None, full_progress_url=None):
    """Call the Get Progress API to check if there is an anonymization running.

    There are two reasons to do this:
        1. Before the first anonymization to check if there is any anonymization running. In this case both parameters
            user_name and full_progress_url must be None / absent.
        2. During our anonymization to check when it is finished. The latest response is stored for each user_name.

    When is an anonymization running, and when it is finished?

    Let's start with the HTTP status codes. 404 means "Returned if there is no user anonymization task found.". It is
    obvious there is no anonymization running. We can return something like "No anon. running".

    There is another status code documented: 403 "Returned if the logged-in user cannot anonymize users.". This is a
    problem the script has handled before the anonymization has been scheduled and is not checked here with
    regards to the running-status (in fact at the end of this function there is a r.raise_for_status() as a lifeline
    in case I haven't implemented a bullet-proof permission check earlier).

    There is the HTTP status code 200 left. If that is returned, I have to look into the JSON responses "status"-
    attribute. I haven't a mapping of HTTP status-code to progress "status"-attribute yet, by I have the list of
     "status" values read from the Jira source code (jira-project/jira-components/jira-plugins/jira-rest/jira-rest-plugin/src/main/java/com/atlassian/jira/rest/v2/user/anonymization/UserAnonymizationProgressBean.java):
    These are:
      - COMPLETED The anonymization process finished. Some errors or warnings might be present.
      - INTERRUPTED There is no connection with the node that was executing the anonymization process. Usually, this
            means that the node crashed and the anonymization task needs to be cleaned up from the cluster.
      - IN_PROGRESS The anonymization process is still being performed.
      - VALIDATION_FAILED The anonymization process hasn't been started because the validation has failed for some
            anonymization handlers.

    As a conclusion I can say:

    HTTP status | "status" attribute| Anonymization not running (anymore) / is finished |   Anonymization is running
        404     |   don't care      |   Yes                                                     No
        200     |   IN_PROGRESS     |   No                                                      Yes
        200     |   other           |   Yes                                                     No

    The "errors" and "warnings" are not evaluated in this implementation step. Maybe later. I assume the validation
    does the job to show errors, and the filter will filter user out in case of errors.

    :param user_name: Optional. Given if there have been scheduled one of our anonymizations. In this case, the
        full_progress_url is also mandatory.
    :param full_progress_url: Optional. Given if there have been scheduled one of our anonymizations. In this case,
        the user_name is also mandatory.
    :return: The progress (percentage) from the returned JSON. -1 if HTTP-status is 404 ("Returned if there is no user
        anonymization task found.").
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
    if r.status_code == 200:
        if r.json()['status'] == 'IN_PROGRESS':
            progress_percentage = r.json()['currentProgress']
        else:
            # Don't know if the API returns "currentProgress" and 100 in all other cases than IN_PROGRESS, so I
            # force it to be 100.
            progress_percentage = 100
    elif r.status_code == 404:
        # "Returned if there is no user anonymization task found."
        progress_percentage = -1
    log.debug("progress_percentage {}".format(progress_percentage))

    # For any other HTTP status:
    if progress_percentage is None:
        r.raise_for_status()

    return progress_percentage


def get_applicationuser_data_from_rest():
    """Read the ID, USER_KEY, LOWER_USER_NAME, and ACTIVE from Jira-DB for the user-names given as the dict-keys and
    supplement it to the dict.

    This functions assumes there is the REST endpoint ANONHELPER_APPLICATIONUSER_URL available!

    :return:    Nothing.
    """
    rel_url = ANONHELPER_APPLICATIONUSER_URL
    log.info("GET {}".format(rel_url))
    url = g_config['jira_base_url'] + rel_url
    for user_name in g_users.keys():
        url_params = {'username': user_name}
        r = g_session.get(url=url, params=url_params)
        g_users[user_name]['rest_get_applicationuser'] = serialize_response(r)


def wait_until_anonymization_is_finished_or_timedout(user_name):
    """Wait until the anonymization for the given user has been finished.
    :param user_name: The user-anonymization to wait for.
    :return: 0 if anonymization finished within the timeout. Otherwise the seconds waited until the timeout.
    """
    log.info("for user {}".format(user_name))
    user_data = g_users[user_name]
    url = g_config['jira_base_url'] + user_data['rest_post_anonymization']['json']['progressUrl']
    seconds_waited = 0
    # Print progress once a minute
    next_progress_print_at = 60
    while g_config['timeout'] <= 0 or seconds_waited < g_config['timeout']:
        progress_percentage = get_anonymization_progress(user_name, url)
        if seconds_waited >= next_progress_print_at:
            log.info("Progress {}".format(progress_percentage))
            next_progress_print_at += 60
        if progress_percentage == 100 or progress_percentage == -1:
            seconds_waited = 0
            break
        time.sleep(g_config['regular_delay'])
        seconds_waited += g_config['regular_delay']
    return seconds_waited


def run_user_anonymization(valid_users, new_owner_key):
    rel_url_for_deletion = '/rest/api/2/user'
    rel_url_for_anonymizing = '/rest/api/2/user/anonymization'

    if g_config['is_try_delete_user']:
        phrase = "delete or "
    else:
        phrase = ""

    log.info("Going to {}anonymize {} users".format(phrase, len(valid_users), rel_url_for_anonymizing))
    if g_config['is_dry_run']:
        log.warning("DRY-RUN IS ENABLED. No user will be deleted nor anonymized.")

    url_for_deletion = g_config['jira_base_url'] + rel_url_for_deletion
    url_for_anonymizing = g_config['jira_base_url'] + rel_url_for_anonymizing
    for user_name, user_data in valid_users.items():
        user_key = user_data['rest_get_user__before_anonymization']['json']['key']
        log.info("for user (name/key) {}/{}".format(user_name, user_key))
        body = {"userKey": user_key, "newOwnerKey": new_owner_key}
        if not g_config['is_dry_run']:
            is_user_deleted = False
            if g_config['is_try_delete_user']:
                url_params = {'username': user_name}
                r = g_session.delete(url=url_for_deletion, params=url_params)
                user_data['rest_delete_user'] = serialize_response(r)
                log.debug(user_data['rest_delete_user'])
                if r.status_code == 204:
                    is_user_deleted = True
                    user_data['rest_user_delete_time'] = now_to_date_string()

            if not is_user_deleted:
                r = g_session.post(url=url_for_anonymizing, json=body)
                user_data['rest_post_anonymization'] = serialize_response(r)
                log.debug(user_data['rest_post_anonymization'])

                if r.status_code == 202:
                    log.debug("Waiting the initial delay of {}s".format(g_config["initial_delay"]))
                    time.sleep(g_config['initial_delay'])
                    waited = wait_until_anonymization_is_finished_or_timedout(user_name)
                    if waited > 0:
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


def get_anonymized_user_data_from_rest(anonymized_users):
    rel_url = '/rest/api/2/user'
    log.info("for all anonymized users".format(rel_url))
    url = g_config['jira_base_url'] + rel_url
    for user_name, user_data in anonymized_users.items():
        anonymized_user_name = 'jirauser{}'.format(user_data['rest_get_applicationuser']['json'][user_name]['id'])
        url_params = {'username': anonymized_user_name}
        r = g_session.get(url=url, params=url_params)
        g_users[user_name]['rest_get_user__query_anonymized_user'] = serialize_response(r)
        log.debug(g_users[user_name]['rest_get_user__query_anonymized_user'])


def is_any_anonymization_running():
    log.info("?")
    progress_percentage = get_anonymization_progress()
    if progress_percentage == 100 or progress_percentage == -1:
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
    number_of_deleted_users = 0
    number_of_anonymized_users = 0
    users_data = overall_report['users_from_infile']
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
            if not user_filter['is_anonymize_approval']:
                number_of_skipped_users += 1
            filter_is_anonymize_approval = user_filter['is_anonymize_approval']
            filter_error_message = user_filter['error_message']
        except KeyError:
            user_filter = {}
            filter_is_anonymize_approval = None
            filter_error_message = None

        try:
            time_start = user_data['rest_user_delete_time']
            time_finish = None
            is_deleted = user_data['rest_delete_user']['status_code'] == 204
            if is_deleted:
                number_of_deleted_users += 1
        except KeyError:
            time_start = None
            time_finish = None
            is_deleted = False

        is_anonymized = False
        if not is_deleted:
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

        if is_feature_do_report_anonymized_user_data_enabled():
            if is_anonymized:
                try:
                    anonymized_user_name = user_data['rest_get_user__query_anonymized_user']['json']['name']
                    anonymized_user_key = user_data['rest_get_user__query_anonymized_user']['json']['key']
                    anonymized_user_display_name = user_data['rest_get_user__query_anonymized_user']['json'][
                        'displayName']
                except KeyError:
                    # This is an error! Let the user know.
                    assert False, "The user '{}' was anonymized and the feature/API {} is functional," \
                                  "but the anonymized user-name could not retrieved".format(
                        user_name, ANONHELPER_APPLICATIONUSER_URL)
            else:
                anonymized_user_name = ""
                anonymized_user_key = ""
                anonymized_user_display_name = ""

            user_report['anonymized_user_name'] = anonymized_user_name
            user_report['anonymized_user_key'] = anonymized_user_key
            user_report['anonymized_user_display_name'] = anonymized_user_display_name

        if is_deleted:
            user_report['action'] = "deleted"
        elif is_anonymized:
            user_report['action'] = "anonymized"
        else:
            user_report['action'] = "skipped"

        report["users"].append(user_report)

    report['overview'] = {
        'number_of_users_in_infile': len(users_data),
        'number_of_skipped_users': number_of_skipped_users,
        'number_of_deleted_users': number_of_deleted_users,
        'number_of_anonymized_users': number_of_anonymized_users,
        # There is one more attribute: is_background_reindex_triggered. This will be set later just before triggering
        # a re-index. But for printing the report, this attribute has to be present. Set it to False as the default.
        'is_background_reindex_triggered': False
    }
    return report


def write_reports(report):
    """Write the data got from the raw-report to files as a) a JSON and b) as CSV.
    :param report:
    :return:
    """
    with open(g_config['report_json_filename'], 'w', encoding=g_config['encoding']) as f:
        print("{}".format(json.dumps(report, indent=4)), file=f)

    with open(g_config['report_text_filename'], 'w', newline='', encoding=g_config['encoding']) as f:
        fieldnames = ['user_name', 'user_key', 'user_display_name', 'active',
                      'validation_has_errors',
                      'filter_is_anonymize_approval', 'filter_error_message',
                      'action',
                      'time_start', 'time_finish', 'time_duration']
        if is_feature_do_report_anonymized_user_data_enabled():
            fieldnames.extend(['anonymized_user_name', 'anonymized_user_key', 'anonymized_user_display_name'])

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report['users'])


def recreate_reports():
    with open(g_config['report_details_filename'], 'r', encoding=g_config['encoding']) as f:
        overall_report = json.load(f)
        # The overall-report was written from the g_details.
        report = create_raw_report(overall_report)
        write_reports(report)


def write_result_to_stdout(overview):
    print("Anonymizing Result:")
    print("  Users in infile:   {}".format(overview['number_of_users_in_infile']))
    print("  Skipped users:     {}".format(overview['number_of_skipped_users']))
    print("  Deleted users:     {}".format(overview['number_of_deleted_users']))
    print("  Anonymized users:  {}".format(overview['number_of_anonymized_users']))
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
    return date_time.strftime('%Y-%m-%dT%H:%M:%S')


def now_to_date_string():
    return to_date_string(datetime.now())


def at_exit():
    """Regardless of the exit-reason, write the reports."""

    try:
        # Check if finished-date is present. If not, the script was aborted.
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
    write_reports(raw_report)
    write_result_to_stdout(raw_report['overview'])

    with open(g_config['report_details_filename'], 'w', encoding=g_config['encoding']) as f:
        print("{}".format(json.dumps(get_sanitized_global_details(), indent=4)), file=f)


def main():
    g_details['execution']['script_started'] = now_to_date_string()
    args = parse_parameters()

    if args.subparser_name == 'validate' or args.subparser_name == 'anonymize':
        atexit.register(at_exit)
        log.debug("")
        read_user_names_from_infile()
        log.debug("")
        get_users_data_from_rest()
        log.debug("")
        get_validation_data_from_rest()
        if is_feature_do_report_anonymized_user_data_enabled():
            log.debug("")
            get_applicationuser_data_from_rest()
        log.debug("")
        filter_users()

        if args.subparser_name == 'anonymize':
            log.debug("")
            if is_any_anonymization_running():
                log.error("There is an anonymization running, or the status of anonymization couldn't be read."
                          " In both cases this script must not continue because these cases are not handled."
                          " Exiting.")
                sys.exit(2)
            log.debug("")
            anonymized_users = {user_name: user_data for (user_name, user_data) in g_users.items() if
                                user_data['user_filter']['is_anonymize_approval'] is True}
            if not g_config['dry_run']:
                # run_user_anonymization() expects the user-key, not the user-name.
                new_owner_key = g_execution['rest_get_user__new_owner']['json']['key']
                run_user_anonymization(anonymized_users, new_owner_key)
                if is_feature_do_report_anonymized_user_data_enabled():
                    log.debug("")
                    get_anonymized_user_data_from_rest(anonymized_users)

        # Re-indexing is specific to the "if args.subparser_name == 'anonymize'". But the re-index shall only be
        # triggered if there is at least one anonymized user. Only the report provides information about the number of
        # anonymized users, so we have to create the report fist.
        raw_report = create_raw_report(g_details)
        if raw_report['overview']['number_of_anonymized_users'] > 0 and args.is_do_background_reindex:
            # Let the user know if a re-index has been triggered.
            # The following attribute 'is_background_reindex_triggered' is not the parameter
            # 'is_do_background_reindex' got from the command-line.
            raw_report['overview']['is_background_reindex_triggered'] = True
            trigger_reindex()

        g_details['execution']['script_finished'] = now_to_date_string()
        g_details['execution']['is_script_aborted'] = False

        # Let at_exit() write the reports.


if __name__ == '__main__':
    main()

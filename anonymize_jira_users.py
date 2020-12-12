#!/usr/bin/python3

"""
Compatibility:  Python 3.7


TODO Prevent users from be anonymized a second time
TODO Final OK or error overview
TODO Jira 8.14 supports user-access-token? Support it.
TODO Parameter for usage without/with appuser-REST-API
TODO In REST endpoint /rest/scriptrunner/latest/custom/appuser, implement access-permission the same way as Atlassian
    does in anonymization API.
TODO Implement progress bar
TODO Known issues:
TODO The returned error-messages in the JSON-responses are expected in the language-setting of the executing admin.
        But they're sometime in a different language. Is this "different language" the one of the user to be
        anonymized, or the Jira-system-default-language? Or other?

"""

import argparse
import atexit
import csv
import json
import logging
import re
import sys
import time
from pathlib import Path

import requests

#
#  Global constants: Defaults
#
#  Defaults comprise of a dictionary and some variables. The dictionary is also taken to generate an example-
#  configuration with command line option -g.
#  All configurations which must not configurable by the user are variables.
#

VERSION = "1.0.0-SNAPSHOT"

DEFAULT_CONFIG = {
    "base_url": "",
    "admin_user": "",
    "admin_pw": "",
    "config_template": "my-config.json",
    "infile": "usernames.txt",
    "out_details_file": "anonymizing_details.json",
    "out_report_text_file": "anonymizing_report.txt",
    "out_report_json_file": "anonymizing_report.json",
    "loglevel": "INFO",
    "is_dry_run": True,
    "new_owner_key": "",
    # Delay between a scheduled anonymization and starting querying the progress. Jira's value is 10s.
    "initial_delay": 10,
    # Interval between progress-queries. Jira's value is 3s
    "regular_delay": 3,
    # 15min is only a rule of thump. In large instances, especially with an Oracle-DB, an anonymization
    # could take longer (I think). Oracle seems to be slow in my experience. See also
    "timeout": 15 * 60
}

DEFAULT_CONFIG_TEMPLATE_FILENAME = "my-config.json"

#
#  Global vars.
#

log = logging.getLogger()
g_config = DEFAULT_CONFIG

# The user data.
#   - key: user-name
#   - value:
#       - rest_user
#       - rest_validation
#       - filter
#           - error_message
#           - anonymize_approval
#       - rest_anonymization
#       - rest_last_anonymization_progress
g_users = {}

# The collected data.
# The keys are:
#   - effective_config
#   - usernames_from_infile
g_details = {
    "effective_config": g_config,
    "usernames_from_infile": g_users
}


def create_config_template(filename):
    with open(filename, 'w') as f:
        print("{}".format(json.dumps(DEFAULT_CONFIG, indent=4)), file=f)


def merge_dicts(d1, d2):
    """
    Merge d2 into d1. Take only non-None-properties into account.
    :param d1: The dict d2 is merged to.
    :param d2: The dict to be merged to d1
    :return: None
    """
    res = d1.copy()
    for k, v in d2.items():
        if k not in d1 and v is not None:
            res[k] = v
        elif k in d1 and v is not None:
            res[k] = v
    d1.clear()
    d1.update(res)


def check_parameters():
    """
    Handle the arguments.
    :return: The args-object.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(VERSION))
    parser.add_argument("-r", "--recreate-report", action="store_true",
                        help="Re-create the reports form the details file. Only for development.")

    sp = parser.add_subparsers(dest="subparser_name")
    sp_validate = sp.add_parser("validate")
    sp_anonymize = sp.add_parser("anonymize")

    parser.add_argument("-g", "--generate-config-template",
                        const=DEFAULT_CONFIG_TEMPLATE_FILENAME,
                        nargs='?',
                        metavar="CONFIG_TEMPLATE_NAME",
                        help="Generate a configuration-template. Defaults to {}.".format(
                            DEFAULT_CONFIG_TEMPLATE_FILENAME))

    # Add arguments for "validated" as well as "anonymized".
    for index, sub_parser in enumerate([sp_validate, sp_anonymize]):
        if index == 0:
            verb = "validated"
        elif index == 1:
            verb = "anonymized"
        else:
            verb = ""

        sub_parser.add_argument("-c", "--config-file",
                                help="Config-file. You can generate one with option 'config -g'."
                                     " Parameters given on the command line will overwrite parameters"
                                     " given in the config-file.")
        sub_parser.add_argument("-b", "--base-url", help="Jira base-URL.")
        sub_parser.add_argument("-u", "--admin-user", help="Admin user-name who will perform the anonymization.")
        sub_parser.add_argument("-p", "--admin-pw", help="Admin password.")
        sub_parser.add_argument("-i", "--infile",
                                help="File with user-names to be {}. One user-name per line."
                                     " No other delimiters are allowed, as space, comma, semicolon and some other"
                                     " special characters allowed in user-names."
                                     " Defaults to {}".format(verb, DEFAULT_CONFIG["infile"]))
        sub_parser.add_argument("-o", "--out-report-file",
                                help="Report with brief information about the {} users. Defaults to {}.".format(
                                    verb, DEFAULT_CONFIG["out_report_text_file"]))
        sub_parser.add_argument("-d", "--out-details-file",
                                help="Detailed information about the {} users. Defaults to {}.".format(
                                    verb, DEFAULT_CONFIG["out_details_file"]))
        sub_parser.add_argument("-l", "--loglevel",
                                choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                                help="Log-level. Defaults to {}".format(DEFAULT_CONFIG["loglevel"]))

    # Add argument special to "anonymize".
    sp_anonymize.add_argument("-n", "--new-owner-key", metavar="NEW_OWNER_KEY", dest="new_owner_key",
                              help="Transfer all roles to the user with this user key.")
    sp_anonymize.add_argument("-D", "--dry-run", action="store_true",
                              help="Finally do no anonymize. Skip the POST /rest/api/2/user/anonymization.")

    parser.parse_args()
    args = parser.parse_args()

    merge_dicts(g_config, vars(args))

    # g_config["subparser_name"] = args.subparser_name
    # print("************ g_config {}", format(g_config["subparser_name"]))

    if args.recreate_report:
        recreate_reports()
        sys.exit(0)

    if args.generate_config_template:
        create_config_template(args.generate_config_template)
        sys.exit(0)

    if args.subparser_name == "validate" or args.subparser_name == "anonymize":
        if args.config_file:
            with open(args.config_file) as f:
                config_from_file = json.load(f)
                merge_dicts(g_config, config_from_file)

        missing_args = []
        if not g_config["base_url"]:
            missing_args.append("base-url")
        if not g_config["admin_user"]:
            missing_args.append("admin-user")
        if not g_config["admin_pw"]:
            missing_args.append("admin-pw")
        if missing_args:
            print("Missing arguments: {}".format(missing_args))
            sys.exit(1)

    #
    #  Configure logging.
    #

    # Set basicConfig() to get levels less than WARNING running in our logger.
    # See https://stackoverflow.com/questions/56799138/python-logger-not-printing-info
    logging.basicConfig(level=logging.WARNING)
    # Set a useful logging-format. Not the most elegant way, but it works.
    log.handlers[0].setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(funcName)s(): %(message)s'))
    # See also https://docs.python.org/3/howto/logging.html:
    numeric_level = getattr(logging, g_config["loglevel"], None)
    # The check for valid values have been done in parser.add_argument().
    log.setLevel(numeric_level)

    # Check infile for existence.
    try:
        open(g_config["infile"])
    except IOError:
        log.error("Infile {} does not exist or is not accessible".format(g_config["infile"]))
        sys.exit(1)

    return args


def read_user_names_from_infile():
    """
    Read the Jira user-names from the infile and put them as keys to the global dict.

    :return: Nothing.
    """
    log.info("Reading user-names from infile {}".format(g_config["infile"]))
    inputfile = Path(g_config["infile"]).read_text().strip()
    user_names = re.split("[\n\r]+", inputfile)
    log.info("  The user-names are: {}".format(user_names))
    for user_name in user_names:
        g_users[user_name] = {}


def serialize_response(r):
    # The body is a b'String in Python 3 and is not readable by json.dumps(). It has to be decoded before.
    # The 'utf-8' is only a suggestion here.
    decoded_body = r.request.body.decode('utf-8') if r.request.body else None
    return {"status_code": r.status_code, "json": r.json(), "requst_body": decoded_body,
            "requst_method": r.request.method, "requst_url": r.request.url}


def read_users_data_from_rest():
    rel_url = "/rest/api/2/user"
    log.info("Reading user-data from GET {}".format(rel_url))
    url = g_config["base_url"] + rel_url
    for user_name in g_users.keys():
        url_params = {"username": user_name}
        r = requests.get(auth=(g_config["admin_user"], g_config["admin_pw"]), url=url, params=url_params)
        g_users[user_name]["rest_user"] = serialize_response(r)
        log.debug(g_users[user_name]["rest_user"])


def get_validate_user_anonymizations_from_rest():
    """
    Validate all Jira-users whose user-keys could be requested in read_appuser_data(). Store the validation-response
    to the dict.

    :return: Nothing.
    """
    rel_url = "/rest/api/2/user/anonymization"
    log.info("Reading validation-data (GET {})".format(rel_url))
    url = g_config["base_url"] + rel_url
    for user_name, user_data in g_users.items():
        if user_data["rest_user"]["status_code"] != 200:
            # The user does not exist. A message about this missing user is logged later on
            # in filter_users()
            continue

        user_key = user_data["rest_user"]["json"]["key"]
        # &expand=affectedEntities: This is like Atlassian does this in the UI
        url_params = {"userKey": user_key, "expand": "affectedEntities"}
        r = requests.get(auth=(g_config["admin_user"], g_config["admin_pw"]), url=url, params=url_params)
        g_users[user_name]["rest_validation"] = serialize_response(r)
        log.debug(g_users[user_name]["rest_validation"])

        # These status-codes are documented:
        #  - 200 Returned when validation succeeded.
        #  - 400 Returned if a mandatory parameter was not provided or validation failed.
        #  - 403 Returned if the logged-in user cannot anonymize users
        if not (r.status_code == 200 or r.status_code == 400 or r.status_code == 403):
            # For all other not documented HTTP-problems:
            r.raise_for_status()


def filter_users():
    log.info("Filtering users by existence and against validation result")

    for user_name, user_data in g_users.items():
        error_message = ""

        #
        #  Check against data got form GET /rest/api/2/user if the user exists and is inactive
        #
        if user_data["rest_user"]["status_code"] != 200:
            error_message = "{}".format(user_data["rest_user"]["json"]["errorMessages"][0])
        else:
            # Check if the existing user is an active user:
            is_active_user = user_data["rest_user"]["json"]["active"]
            if is_active_user:
                error_message = "Is an active user. Only inactive users will be anonymized."

        #
        #  Check against validation result got from GET rest/api/2/user/anonymization.
        #
        if not error_message:
            # try/except: user_data["rest_validation"] could be absent in case of an invalid user-name.
            try:
                if user_data["rest_validation"]["status_code"] != 200:
                    error_message = "HTTP status-code is not 200. "
                # Despite of an status-code of 200 there could be errors (seen in use case "admin tries to
                # anonymize themsellf).
                if len(user_data["rest_validation"]["json"]["errors"]) > 0:
                    error_message += "There is at least one validation error message: {}".format(
                        user_data["validation"]["errors"])
            except KeyError:
                pass

        user_data["filter"] = {}
        user_data["filter"]["error_message"] = ""
        if error_message:
            user_data["filter"]["error_message"] = error_message
            user_data["filter"]["anonymize_approval"] = False
            log.warning(user_name + ": " + error_message)
        else:
            user_data["filter"]["anonymize_approval"] = True

    vu = {user_name: user_data for (user_name, user_data) in g_users.items() if
          user_data["filter"]["anonymize_approval"] is True}
    log.info("Remaining users to be anonymized: {}".format(list(vu.keys())))


def get_anonymization_progress(user_name=None, fullProgressUrl=None):
    """
    Call the Get Progress API to check if there is an anonymization running.

    There are two reasons to do this:
        1. Before the first anonymization to check if there is any anonymization running. In this case both parameters
            user_name and progressUrl are emtpy.
        2. During our anonymization to check when it is finished. Per user_name the latest responses ist stored.

    When is an anonymization running, and when it has been finished?

    Let's start with the HTTP status codes. 404 means "Returned if there is no user anonymization task found.". It is
    obvious there is no anonymization running. I can return something like "No anon. running".
    There is another status code documented: 403 "Returned if the logged-in user cannot anonymize users.". This is a
    problem I assume I have been handled before my anonymization has been scheduled and is not checked here with
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

    HTTP status | "status" attribute| Anonymization not running (anymore) / is finished |   Running
        404     |   don't care      |   Yes                                                     No
        200     |   IN_PROGRESS     |   No                                                      Yes
        200     |   other           |   Yes                                                     No

    The "errors" and "warnings" are not evaluated in this implementation step. Maybe later. I assume the validation
    does the job to show errors, and the filter will filter user out in case of errors.

    :param user_name: Optional. Given if there have been scheduled one of our anonymizations.
    :param fullProgressUrl: Optional. Given if there have been scheduled one of our anonymizations.
    :return: Empty string, if anonymization is running. Otherwise the
    """
    if fullProgressUrl:
        url = fullProgressUrl
        # Only DEBUG, because this could be called a lot.
        log.debug("Checking from GET {} if specific anonymization is running".format(url))
    else:
        rel_url = "/rest/api/2/user/anonymization/progress"
        url = g_config["base_url"] + rel_url
        log.info("Checking if any anonymization is running")
    r = requests.get(auth=(g_config["admin_user"], g_config["admin_pw"]), url=url)
    # If this call is for a specific user/anonymization-task, store the response in the user's data.
    if user_name:
        g_users[user_name]["rest_last_anonymization_progress"] = serialize_response(r)
        log.debug(g_users[user_name]["rest_last_anonymization_progress"])

    progress_percentage = None
    if r.status_code == 200:
        if r.json()["status"] == "IN_PROGRESS":
            progress_percentage = r.json()["status"] == "currentProgress"
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


def read_appuser_data():
    """
    Read the ID, USER_KEY, LOWER_USER_NAME, and ACTIVE from Jira-DB for the user-names given as the dict-keys and
    supplement it to the dict.

    This functions assumes there is the REST endpoint /rest/scriptrunner/latest/custom/appuser available!

    :return:    Nothing.
    """
    rel_url = "/rest/scriptrunner/latest/custom/appuser"
    log.info("Reading appuser-data from GET {}".format(rel_url))
    url = g_config["base_url"] + rel_url
    for user_name in g_users.keys():
        g_users[user_name]["appuser"] = {
            "request-type": "GET",
            "url": url}
        url_params = {"username": user_name}
        r = requests.get(auth=(g_config["admin_user"], g_config["admin_pw"]), url=url, params=url_params)
        g_users[user_name]["appuser"].update({
            "status_code": r.status_code,
            "response": r.json()})


def wait_until_anonymization_has_finished(user_name):
    """

    :param user_name: The user to be waited for.
    :return: 0 if anonymization finished within the timeout. Otherwise the seconds waited until the timeout.
    """
    log.info("for user {}".format(user_name))
    user_data = g_users[user_name]
    url = g_config["base_url"] + user_data["rest_anonymization"]["json"]["progressUrl"]
    seconds_waited = 0
    while seconds_waited < g_config["timeout"]:
        progress_percentage = get_anonymization_progress(user_name, url)
        if progress_percentage == 100 or progress_percentage == -1:
            seconds_waited = 0
            break
        time.sleep(g_config["cyclic_delay"])
        seconds_waited += g_config["cyclic_delay"]
    return seconds_waited


def run_user_anonymizations(new_owner_key):
    rel_url = "/rest/api/2/user/anonymization"
    valid_users = {user_name: user_data for (user_name, user_data) in g_users.items() if
                   user_data["filter"]["anonymize_approval"] is True}
    log.info("Going to run anonymization for {} users (POST {})".format(len(valid_users), rel_url))
    if g_config["is_dry_run"]:
        log.warning("DRY-RUN IS ENABLED. No user will be anonymized.")

    url = g_config["base_url"] + rel_url
    for user_name, user_data in valid_users.items():
        user_key = user_data["rest_user"]["json"]["key"]
        log.info("Schedule user anonymizing for user (name/key) {}/{}...".format(user_name, user_key))
        body = {"userKey": user_key, "newOwnerKey": new_owner_key}
        if not g_config["is_dry_run"]:
            r = requests.post(auth=(g_config["admin_user"], g_config["admin_pw"]), url=url, json=body)
            user_data["rest_anonymization"] = serialize_response(r)
            log.debug(user_data["rest_anonymization"])

            if r.status_code == 202:
                # This should be the INITIAL_DELAY of 10s. but I shorten it to the REGULAR_DELAY of 3s.
                time.sleep(g_config["regular_delay"])
                waited = wait_until_anonymization_has_finished(user_name)
                if waited > 0:
                    log.error(
                        "Anonymizing of user '{}' took longer than the configured timeout of {} seconds. Abort script."
                            .format(user_name, g_config["timeout"]))
                    break
            else:
                # These error-status-codes are documented:
                #  - 400 Returned if a mandatory parameter was not provided.
                #  - 403 Returned if the logged-in user cannot anonymize users.
                #  - 409 Returned if another user anonymization process is already in progress.
                if r.status_code == 400 or r.status_code == 403 or r.status_code == 409:
                    log.error(
                        "A problem occurred scheduling anonymizing user {}. See report {} for details.".format(
                            user_name, g_config["out_details_file"]))
                else:
                    # For all other, not documented HTTP-problems:
                    r.raise_for_status()


def is_any_anonymization_running():
    log.info("?")
    progress_percentage = get_anonymization_progress()
    if progress_percentage == 100 or progress_percentage == -1:
        log.info("No")
        return False
    else:
        log.info("  Yes")
        return True


def create_json_report(users_details):
    json_report = []
    for user_name, user_data in users_details.items():

        try:
            start_time = user_data["rest_last_anonymization_progress"]["json"]["startTime"]
            finish_time = user_data["rest_last_anonymization_progress"]["json"]["finishTime"]
            is_anonymized = user_data["rest_last_anonymization_progress"]["status_code"] == 200 and \
                            user_data["rest_last_anonymization_progress"]["json"]["status"] == "COMPLETED"
        except KeyError:
            start_time = ""
            finish_time = ""
            is_anonymized = False

        try:
            user_key = user_data["rest_user"]["json"]["key"]
            user_display_name = user_data["rest_user"]["json"]["displayName"]
            active = user_data["rest_user"]["json"]["active"]
        except KeyError:
            user_key = ""
            user_display_name = ""
            active = ""

        try:
            filter = user_data["filter"]
        except KeyError:
            filter = {}

        try:
            has_validation_errors = len(user_data["rest_validation"]["errors"]) > 0
        except:
            has_validation_errors = False

        user_json_report = {
            "user_name": user_name,
            "is_anonymized": is_anonymized,
            "user_key": user_key,
            "user_display_name": user_display_name,
            "active": active,
            "filter_anonymize_approval": filter["anonymize_approval"],
            "filter_error_message": filter["error_message"],
            "has_validation_errors": has_validation_errors,
            "start_time": start_time,
            "finish_time": finish_time
        }
        json_report.append(user_json_report)

    return json_report


def recreate_reports():
    with open(g_config["out_details_file"]) as f:
        d = json.load(f)["usernames_from_infile"]
        write_reports(d)


def write_reports(d):
    json_report = create_json_report(d)

    with open(g_config["out_report_json_file"], 'w') as f:
        print("{}".format(json.dumps(json_report, indent=4)), file=f)

    with open(g_config["out_report_text_file"], 'w') as f:
        fieldnames = ["user_name", "is_anonymized", "user_key", "user_display_name", "active",
                      "filter_anonymize_approval", "filter_error_message", "has_validation_errors", "start_time",
                      "finish_time"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(json_report)


def at_exit():
    # print("{}".format(g_details))

    try:
        is_g = g_config["g"]
    except KeyError:
        is_g = False

    if not (is_g):
        with open(g_config["out_details_file"], 'w') as f:
            print("{}".format(json.dumps(g_details, indent=4)), file=f)


def main():
    args = check_parameters()

    if args.subparser_name == "validate" or args.subparser_name == "anonymize":
        atexit.register(at_exit)
        log.debug("")
        read_user_names_from_infile()
        log.debug("")
        read_users_data_from_rest()
        log.debug("")
        get_validate_user_anonymizations_from_rest()
        log.debug("")
        filter_users()

        if args.subparser_name == "anonymize":
            log.debug("")
            if is_any_anonymization_running():
                log.error("There is an anonymization running, or the status of anonymization couldn't be read."
                          " In both cases this script must not continue because these cases are not implemented. Exiting.")
                sys.exit(2)
            log.debug("")
            if not g_config["dry_run"]:
                run_user_anonymizations(g_config["new_owner_key"])

        write_reports(g_details["usernames_from_infile"])


if __name__ == "__main__":
    main()

README
=

Other articles

- [Atlassian: Anonymizing users](https://confluence.atlassian.com/adminjiraserver/anonymizing-users-992677655.html)
- [Atlassian: Retrying anonymization](https://confluence.atlassian.com/adminjiraserver/retrying-anonymization-992677663.html)
- [Me: How anonymizing works with the Jira-UI](doc/How_anonymization_works_with_the_Jira-UI.md)
- [Me: About user-names and user-keys](doc/About_user-names_and_user-keys.md)

User Manual
=

- [General](#general)
- [Quick-start](#quick-start)
- [Command Line Options](#command-line-options)
  * [Overview](#overview)
  * [Parameters without command](#parameters-without-command)
  * [Parameters for command "inactive-users"](#parameters-for-command--inactive-users-)
  * [Parameters for command "validate"](#parameters-for-command--validate-)
  * [Parameters for command "anonymize"](#parameters-for-command--anonymize-)
  * [Parameters for command "misc"](#parameters-for-command--misc-)
  * [The config-file](#the-config-file)
  * [Combination of parameters from the config-file and the command-line](#combination-of-parameters-from-the-config-file-and-the-command-line)
  * [Details about some options](#details-about-some-options)
    + [--info](#--info)
    + [--user-list-file and --encoding](#--user-list-file-and---encoding)
    + [--background-reindex](#--background-reindex)
- [How the Anonymizer works](#how-the-anonymizer-works)
- [The reports](#the-reports)
- [The commands in detail](#the-commands-in-detail)
  * [Command "inactive-users"](#command--inactive-users-)
  * [Command "validate"](#command--validate-)
    + [Example 1: Validation succeeded for all users (no validation error at all)](#example-1--validation-succeeded-for-all-users--no-validation-error-at-all-)
    + [Example 2: Validation failed for all users](#example-2--validation-failed-for-all-users)
  * [Command "anonymize"](#command--anonymize-)
    + [About](#about)
    + [Example 1: Anonymization without errors](#example-1--anonymization-without-errors)
- [Example-Workflow](#example-workflow)
- [My Workflow](#my-workflow)
- [Anonymize deleted users](#anonymize-deleted-users)
- [History of anonymization and related functions](#history-of-anonymization-and-related-functions)
- [F. A. Q.](#f-a-q)
  * [Can we Anonymize a user on JIRA Cloud?](#can-we-anonymize-a-user-on-jira-cloud-)
- [Known issues](#known-issues)
  * [Command inactive-users might return a max. of 1000 users](#command-inactive-users-might-return-a-max-of-1000-users)
  * [Validation error-messages in unexpected language](#validation-error-messages-in-unexpected-language)
  * [Anonymization slow in case Jira is connected to an Oracle-DB](#anonymization-slow-in-case-jira-is-connected-to-an-oracle-db)
  * [Tickets at Atlassian](#tickets-at-atlassian)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>





---

# General

The Anonymizer is a Python-script to help Jira-admins anonymizing Jira-users in bulk. It
is compatible to Python >= 3.7.

Atlassian introduced user anonymization in Jira 8.7. So the Anonymizer works in Jira
versions >= 8.7.

All information stated here is about Jira Server and Jira Data Center. Jira Cloud is not
considered (it has no anonymization function at all).

Call dist (TODO, no dists published yet):

    python anonymize_jira_users.pyz ...

Call latest main, in the project root-dir 'anonymize_jira_users':

    python -m zipapp anonymize_jira_users  &&  python anonymize_jira_users.pyz

---

# Quick-start

- Create the file `users.cfg` with the user-names to be anonymized, one user-name per
  line.
- Create a config-file-template: `python anonymize_jira_users.pyz misc -g`. The
  file `my_bare_default_config.cfg` has been created.
- Rename the file, e.g. to `my_config.cfg`.
- In that file, set the attributes `jira_base_url`,
  `jira_auth`, `new_owner`.
- Call `python anonymize_jira_users.pyz validate -c my_config.cfg` to see what would
  happen in case of anonymizing.
- Call `python anonymize_jira_users.pyz anonymize -c my_config.cfg` to execute
  anonymization.
- Have a look at the report `report.csv` or `report.json`. More details about the users
  and the execution are given in `report_details.json`
- Make a background re-index.

---

# Command Line Options

## Overview

Documentation is also available by the command line help `-h`.

The Anonymizer has the following commands:

- `inactive-users`: Retrieves a list of inactive, not yet anonymized users. These users
  are candidates for anonymization.
- `validate`:            Validates user anonymization process. No anonymization is done.
- `anonymize`:           Anonymizes users.
- `misc`:                Bundle diverse functions. Currently `-g`
  to generate a template-config-file is the only function.

The above commands have different parameter-lists.

## Parameters without command

    --version             show program's version number and exit

## Parameters for command "inactive-users"

      -h, --help            show this help message and exit
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Log-level. Defaults to INFO.
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            Config-file to pre-set command-line-options. You can
                            generate a config-file-template with option 'misc -g'.
                            There are parameters in the config-file not present on
                            the command line. Empty parameters in the config-file
                            are ignored. Parameters given on the command line
                            overwrite parameters given in the config-file.
      -b JIRA_BASE_URL, --jira-base-url JIRA_BASE_URL
                            Jira base-URL.
      -a ADMIN_USER_AUTH, --jira-auth ADMIN_USER_AUTH
                            Admin user-authentication. Two auth-types are
                            supported: Basic, and Bearer (starting with Jira
                            8.14). The format for Basic is: 'Basic <user>:<pass>'.
                            The format for Bearer is: 'Bearer <token>'.
      -o REPORT_OUT_DIR, --report-out-dir REPORT_OUT_DIR
                            Output-directory to write the reports into. If it
                            doesn't exist, it'll be created. If you'd like the
                            date included, give something like `date
                            +%Y%m%d-%H%M%S-anonymize-instance1`. Defaults to '.'.
      --info                Print the effective config, and the character-encoding
                            Python suggests, then exit.
      -G EXCLUDE_GROUPS [EXCLUDE_GROUPS ...], --exclude-groups EXCLUDE_GROUPS [EXCLUDE_GROUPS ...]
                            Exclude members of these groups. Multiple groups must
                            be space-separated. If a group contains spaces, the
                            group must be enclosed in single or double. quotes

## Parameters for command "validate"

      -h, --help            show this help message and exit
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Log-level. Defaults to INFO.
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            Config-file to pre-set command-line-options. You can
                            generate a config-file-template with option 'misc -g'.
                            There are parameters in the config-file not present on
                            the command line. Empty parameters in the config-file
                            are ignored. Parameters given on the command line
                            overwrite parameters given in the config-file.
      -b JIRA_BASE_URL, --jira-base-url JIRA_BASE_URL
                            Jira base-URL.
      -a ADMIN_USER_AUTH, --jira-auth ADMIN_USER_AUTH
                            Admin user-authentication. Two auth-types are
                            supported: Basic, and Bearer (starting with Jira
                            8.14). The format for Basic is: 'Basic <user>:<pass>'.
                            The format for Bearer is: 'Bearer <token>'.
      -o REPORT_OUT_DIR, --report-out-dir REPORT_OUT_DIR
                            Output-directory to write the reports into. If it
                            doesn't exist, it'll be created. If you'd like the
                            date included, give something like `date
                            +%Y%m%d-%H%M%S-anonymize-instance1`. Defaults to '.'.
      -i USER_LIST_FILE, --user-list-file USER_LIST_FILE
                            File with user-names to anonymize or just to validate.
                            One user-name per line. Comments are allowed: They
                            must be prefixed by '#' and they must appear on their
                            own line. The character-encoding is platform dependent
                            Python suggests. If you have trouble with the
                            encoding, try out the parameter '--encoding'.
      --encoding ENCODING   Force a character-encoding for reading the user-list-
                            file. Empty means platform dependent Python suggests.
                            If you run on Win or the user-list-file was created on
                            Win, try out one of these encodings: utf-8, cp1252,
                            latin1.
      --expand-validation-with-affected-entities
                            Include 'affectedEntities' in the validation result.
                            This is only for documentation to enrich the detailed
                            report. It doesn't affect the anonymization. Doing so
                            could increase significantly execution time.
      --info                Print the effective config, and the character-encoding
                            Python suggests, then exit.

## Parameters for command "anonymize"

      -h, --help            show this help message and exit
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Log-level. Defaults to INFO.
      -c CONFIG_FILE, --config-file CONFIG_FILE
                            Config-file to pre-set command-line-options. You can
                            generate a config-file-template with option 'misc -g'.
                            There are parameters in the config-file not present on
                            the command line. Empty parameters in the config-file
                            are ignored. Parameters given on the command line
                            overwrite parameters given in the config-file.
      -b JIRA_BASE_URL, --jira-base-url JIRA_BASE_URL
                            Jira base-URL.
      -a ADMIN_USER_AUTH, --jira-auth ADMIN_USER_AUTH
                            Admin user-authentication. Two auth-types are
                            supported: Basic, and Bearer (starting with Jira
                            8.14). The format for Basic is: 'Basic <user>:<pass>'.
                            The format for Bearer is: 'Bearer <token>'.
      -o REPORT_OUT_DIR, --report-out-dir REPORT_OUT_DIR
                            Output-directory to write the reports into. If it
                            doesn't exist, it'll be created. If you'd like the
                            date included, give something like `date
                            +%Y%m%d-%H%M%S-anonymize-instance1`. Defaults to '.'.
      -i USER_LIST_FILE, --user-list-file USER_LIST_FILE
                            File with user-names to anonymize or just to validate.
                            One user-name per line. Comments are allowed: They
                            must be prefixed by '#' and they must appear on their
                            own line. The character-encoding is platform dependent
                            Python suggests. If you have trouble with the
                            encoding, try out the parameter '--encoding'.
      --encoding ENCODING   Force a character-encoding for reading the user-list-
                            file. Empty means platform dependent Python suggests.
                            If you run on Win or the user-list-file was created on
                            Win, try out one of these encodings: utf-8, cp1252,
                            latin1.
      --expand-validation-with-affected-entities
                            Include 'affectedEntities' in the validation result.
                            This is only for documentation to enrich the detailed
                            report. It doesn't affect the anonymization. Doing so
                            could increase significantly execution time.
      --info                Print the effective config, and the character-encoding
                            Python suggests, then exit.
      -n NEW_OWNER, --new-owner NEW_OWNER
                            Transfer roles of all anonymized users to the user
                            with this user-name.
      -x, --background-reindex
                            If at least one user was anonymized, trigger a
                            background re-index.

## Parameters for command "misc"

      -h, --help            show this help message and exit
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Log-level. Defaults to INFO.
      -g [CONFIG_TEMPLATE_FILE], --generate-config-template [CONFIG_TEMPLATE_FILE]
                            Generate a configuration-template. Defaults to my-
                            bare-default-config.cfg.

## The config-file

Most of the command-line-options can be set in a config-file. A template for this file can
be generated with `python anonymize_jira_users.pyz misc -g`.

A minimal config-file consists of:

    [DEFAULT]
    jira_base_url = http://localhost:2990/jira
    jira_auth = Basic admin:admin
    user_list_file = users.cfg
    new_owner = the-new-owner

The full set of parameters are:

    ####
    #
    # Configuration template for config.py
    #
    # General:
    #   - These values are true in any notation: ['yes', 'true', 'on'].
    #   - These values are false in any notation: ['no', 'false', 'off'].
    #
    ####
    
    [DEFAULT]
    
    #   Loglevel. Valid levels are DEBUG, INFO, WARNING, ERROR, CRITICAL.
    #   The given value is the default.
    #loglevel = INFO
    #   Jira base-URL.
    #   The given value is an example.
    #jira_base_url = http://localhost:2990/jira
    #   Admin user-authentication. Two auth-types are supported: Basic, and Bearer(staring with Jira 8.14).
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
    #report_out_dir = .
    #   Include 'affectedEntities' in the validation result. This is only for documentation 
    #   to enrich the detailed report. It doesn't affect the anonymization.
    #   Doing so could increase significantly execution time.
    #   The given value is the default.
    #is_expand_validation_with_affected_entities = False
    #   Transfer roles to the user with this user-name.
    #   The given value is an example.
    #new_owner = new-owner
    #   Initial delay in seconds the Anonymizer waits after the anonymization is
    #   triggered and the first call to get the anonymization-progress.
    #   The default of Jira is 10 seconds, and this is also the default of the Anonymizer.
    #initial_delay = 10
    #   The delay in seconds between calls to get the anonymization-progress.
    #   The default of Jira is 3 seconds, and this is also the default of the Anonymizer.
    #regular_delay = 3
    #   Time in seconds the anonymization shall wait to be finished.
    #   0 (or any negative value) means: Wait as long as it takes.
    #   The given value is the default.
    #timeout = 0
    #   If at least one user was anonymized, trigger a background re-index.
    #   The given value is the default.
    #is_trigger_background_reindex = False

## Combination of parameters from the config-file and the command-line

The Anonymizer has up to three places where configurations could exist:

1. The internal default-configuration.
2. Your settings from the config-file (which overwrites the internal
   default-configuration).
3. Your parameters given on the command line (which overwrites the settings from the
   config-file).

The anonymizer builds an effective configuration from the above configurations.

You can combine parameters from a config-file and the command-line. E.g. if you don't want
your auth-settings stay in a file because you like to check-in this, you can set them at
the command-line using environment-variables:

    export MY_USERNAME=admin
    export MY_PASSWORD=admin
    python anonymize_jira_users.pyz validate -c my_config.cfg -a "Basic $MY_USERNAME:$MY_PASSWORD"

## Details about some options

### --info

Print the effective config, and the character-encoding Python suggests, then exit.

You can combine this parameter with parameters of `validate` and `anonymize`
If `--info` is given in these cases, these commands won't be executed.

### --user-list-file and --encoding

Dependent on how and where the user-list-file was created, you could come into trouble
with the encoding. You can possibly fix this with an explicit character-encoding. To get
an idea what Python suggests on your current platform, execute

`python anonymize_jira_users.pyz validate --info`.

This will print the current configuration as JSON. There'll be the two vars:

    {
        ...
        "locale_getpreferredencoding": "UTF-8",
        "sys_getfilesystemencoding": "utf-8"
        ...
    }

On Windows, this could be

    {
        ...
        "locale_getpreferredencoding": "cp1252",
        "sys_getfilesystemencoding": "utf-8"
        ...
    }

If the file was created on Windows and you execute the Anonymizer on a different platform,
try e.g.:

`python anonymize_jira_users.pyz validate --encoding cp1252 <your options goes here...>`

or play around with other encodings.

### --background-reindex

Background re-indexing could last very long time on large DC-instances.

From [Search indexing](https://confluence.atlassian.com/adminjiraserver/search-indexing-938847710.html):

> On a multi-node Jira Data Center, you can use the Full re-index option without actually
> locking the instance. Therefore, if your Data Center instance has multiple nodes, don't
> bother with a Background re-index. See
> [Re-indexing Jira Data Center with no downtime](https://confluence.atlassian.com/adminjiraserver/search-indexing-938847710.html#Searchindexing-reindexdc)
> for instructions.



---

# How the Anonymizer works

The Anonymizer executes the following steps for the `validation` and the `anonymization`
command:

- Parse and check the parameters.
- Read the user-names from the user-list-file.
- Filter-out duplicate users in user-list-file.
- For each user: Get user-data from
  the [Jira user REST-API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user-getUser)
  .
- Filter-out not-existing users.
- Filter-out active users.
- For each user: Get anonymization validation data from the
  [Jira Anonymization REST API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user/anonymization)
  .
- Filter-out users with validation errors.

If the command `anonymize` is called, additionally to the steps above

- run anonymization for each user with an 'anonymization approval'
  with [Jira Anonymization REST API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user/anonymization)
  . Transfer ownership to the user given in `--new-owner`.

Finally, in both cases `validation` and `anonymization`:

- Create the anonymization-reports.
- Print out a summary to the command line.

The validation is a subset of the anonymization. So validation is done any time the
anonymization is done. With validation only you can get an impression what would happen in
case of anonymization.

The filter-criteria to not anonymize (= to skip), and their filter-error-messages are:

1. The user isn't existent: `The user named 'user-1' does not exist`.
2. The user is active: `Is an active user.`
3. The anonymization validation REST API didn't return 200
   OK: `HTTP status-code of the REST validation API is not 200.` Please have a look at
   the `report_details.json` and
   [Jira Anonymization REST API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user/anonymization)
   .
4. The anonymization validation REST API returned 200 OK with validation-error-message(s):
   `There is at least one validation error message.`
   Please have a look at the `report_details.json`.

About 1) "The user isn't existent":

This is the case if
the [REST API GET /rest/api/2/user](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user-getUser)
can't find the user. Users can't be found for the following reasons:

- The user never existed.
- The user was deleted and Jira < 8.10 is used. In that case, the REST API isn't capable
  to find deleted users. Starting with Jira 8.10, deleted users will be found.

About 2) "The user is active":

Active users could be anonymized by
[Jira Anonymization REST API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user/anonymization)
. But the Anonymizer doesn't do this either.

About 4) Validation-error-messages:

In case of validation-errors, anonymization is prevented ba _Jira_, not by the Anonymizer.

Some figures about durations:

The durations of anonymization depend on the amount of issues, user-custom-fields, and I
think also on the DB-type. E.g. (in Jira 8.13.1):

- MySQL, license 250 users, 25.000 issues: 6 seconds/user
- Oracle, license 2.000 users, 200.000 issues: 12 minutes/user

---

# The reports

The anonymizer creates:

1. report_details.json: Some kind of internal log the Anonymizer writes during its work.
2. report.json: Information about the processed users at commands `validate` and
   `anonymize`.
3. report.csv: Content is as in report.json, but in comma-separated format.
4. A summary on the command-line.

What file is created or if a summary is written depends on the command:

| Report / Command    | inactive-users | validate | anonymize |
| --- | :---: | :---: | :---: |
| report_details.json | Y | Y | Y |
| report.json/.csv | N | Y | Y |
| Summary on cmd-line | N | Y | Y |

The reports contain more information in case of command `anonymize` than in case of
just `validate`.

**About the report-attribute 'deleted'**

Starting with Jira 8.10, the REST API is capable to find deleted users. In that case, the
report-attribute `deleted` contains false or true. In case of Jira < 8.10 the attribute is
empty.

The report.json/.csv are discussed later in the examples for command `validate`
and `anonymize`.


---

# The commands in detail

## Command "inactive-users"

If you like to anonymize users in bulk you first need a list of users. Without the
Anonymizer, you retrieve this list somehow. The command `inactive-users` could ease this.
It retrieves a list of inactive, not yet anonymized users.

You can give groups with users to be excluded by parameter `--exclude-groups`.

This command cannot retrieve deleted users.

Call:

`python anonymize_jira_users.pyz inactive-users -c my_config.cfg --exclude-groups technical_users do_not_anonymize`

This creates the file inactive_users.cfg in the report-out-dir. The content is e.g.:

    # File generated at 2021-01-14T21:36:05
    # Users: 4
    # User attributes: User-name; user-key; display-name; email-address
    
    # User1Post84; JIRAUSER10200; User 1 Post 84; user1post84@example.com
    User1Post84
    
    # User1Pre84; user1pre84; User 1 Pre 84; user1pre84@example.com
    User1Pre84
    
    # User2Post84; JIRAUSER10201; User 2 Post 84; user2post84@example.com
    User2Post84
    
    # User2Pre84; user2pre84; User 2 Pre 84; user2pre84@example.com
    User2Pre84

These users are candidates for anonymization. You should assess them.

## Command "validate"

Let me introduce the use-case dummy-users `User1Pre84` and `User1Post84`.

The first user `User1Pre84` is an inactive, local user, and was created in a Jira-version
before 8.4. As we'll see in the reports, the user-name and the user-key are equal, as Jira
have not decided between them in versions before 8.4. Both are `User1Pre84`, but the
user-key in lower case.

The second user `User1Post84` is also an inactive, local user, but was created in Jira 8.4
or later. Since 8.4, the user-keys are something like JIRAUSER12345. The user-key
of `User1Post84` is `JIRAUSER10200`.

The Anonymizer does not distinguish between users created before or since Jira 8.4. But
just for the case you are curious why some user-keys in the Anonymizer's reports are equal
to the user-names, and some not.

### Example 1: Validation succeeded for all users (no validation error at all)

We'll use the following config-file `my_config.cfg`.

    [DEFAULT]
    jira_base_url = http://localhost:2990/jira
    jira_auth = Basic admin:admin
    user_list_file = assessed_inactive_users.cfg

Further we use the user-list-file `users.cfg` with our two users:

    User1Pre84
    User1Post84

We call:

`python anonymize_jira_users.pyz validate -c my_config.cfg`

The output is:

    2021-04-05 17:48:03,251:INFO:read_users_from_user_list_file users.cfg
    2021-04-05 17:48:03,251:INFO:read_users_from_user_list_file found 2 users: ['User1Pre84', 'User1Post84']
    2021-04-05 17:48:03,251:INFO:filter_by_duplicate 2 users
    2021-04-05 17:48:03,251:INFO:get_user_data for 2 users
    2021-04-05 17:48:03,312:INFO:filter_by_existance 2 users
    2021-04-05 17:48:03,312:INFO:filter_by_active_status 2 users:
    2021-04-05 17:48:03,312:INFO:get_anonymization_validation_data for 2 users
    2021-04-05 17:48:03,312:INFO:get_anonymization_validation_data for 'User1Pre84'
    2021-04-05 17:48:03,394:INFO:get_anonymization_validation_data for 'User1Post84'
    2021-04-05 17:48:03,428:INFO:filter_by_validation_errors 2 users
    2021-04-05 17:48:03,428:INFO:filter_by_validation_errors has approved 2 of 2 users for anonymization: ['User1Pre84', 'User1Post84']
    
    Result:
      Users in user-list-file: 2
      Skipped users: 0
      Validated users: 2

A file report.json has been created and is as follows. The interesting line per user
is `filter_error_message: ""`. This means, the filter has left over both users for
anonymization. In other words:
Both users haven't matched to any criteria to not anonymize a user. So thumps up for both
users.

If the filter had found any criteria to not anonymize a user, it would have given
an `filter_error_message`.

The report.json is:

    {
        "overview": {
            "number_of_users_in_user_list_file": 2,
            "number_of_skipped_users": 0,
            "number_of_validated_users": 2
        },
        "users": [
            {
                "name": "User1Pre84",
                "key": "user1pre84",
                "display_name": "User 1 Pre 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": null,
                "time_finish": null,
                "time_duration": null,
                "anonymized_user_name": "",
                "anonymized_user_key": "",
                "anonymized_user_display_name": "",
                "action": null
            },
            {
                "name": "User1Post84",
                "key": "JIRAUSER10301",
                "display_name": "User 1 Post 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": null,
                "time_finish": null,
                "time_duration": null,
                "anonymized_user_name": "",
                "anonymized_user_key": "",
                "anonymized_user_display_name": "",
                "action": null
            }
        ]
    }

The `action` can be one of the values `skipped` or `anonymized`. The `action`s here
are `skipped` because we validated only. No anonymization has been done.

Beside the report.json the report.csv has been created and looks like the following
screenshot:

![](doc/images/example_1.png)

### Example 2: Validation failed for all users

The users:

- `missplled-user` is not existent
- `User1Pre84` is active
- `user-from-ad` is inactive, but still connected to a _read-only_ directory

Again, the filter does not give the anonymization approval if:

- the user doesn't exist (`missplled-user`), or
- the user is an active user (`User1Pre84`), or
- the anonymization-validation any validation error (`user-from-ad`).

We call again:

`python anonymize_jira_users.pyz validate -c my_config.cfg`

The output is:

    2021-04-05 17:59:46,797:INFO:read_users_from_user_list_file users.cfg
    2021-04-05 17:59:46,797:INFO:read_users_from_user_list_file found (3) users: ['missplled-user', 'User1Pre84', 'user-from-ad']
    2021-04-05 17:59:46,797:INFO:filter_by_duplicate 3 users
    2021-04-05 17:59:46,797:INFO:get_user_data for 3 users
    2021-04-05 17:59:46,900:INFO:filter_by_existance 3 users
    2021-04-05 17:59:46,901:INFO:filter_by_existance 'missplled-user': Skip. The user named 'missplled-user' does not exist
    2021-04-05 17:59:46,901:INFO:filter_by_active_status 2 users:
    2021-04-05 17:59:46,901:INFO:filter_by_active_status 'User1Pre84': Skip. Is an active user.
    2021-04-05 17:59:46,901:INFO:get_anonymization_validation_data for 1 users
    2021-04-05 17:59:46,901:INFO:filter_by_validation_errors 1 users
    2021-04-05 17:59:46,901:INFO:filter_by_validation_errors has approved 0 of 1 users for anonymization: []

    Result:
      Users in user-list-file: 3
      Skipped users: 3
      Validated users: 0

Have a look at the attribute `filter_error_message` in the report.json:

    {
        "overview": {
            "number_of_users_in_user_list_file": 3,
            "number_of_skipped_users": 3,
            "number_of_validated_users": 0
        },
        "users": [
            {
                "name": "missplled-user",
                "key": null,
                "display_name": null,
                "active": null,
                "deleted": null,
                "filter_error_message": "The user named 'missplled-user' does not exist",
                "time_start": null,
                "time_finish": null,
                "time_duration": null,
                "anonymized_user_name": "",
                "anonymized_user_key": "",
                "anonymized_user_display_name": "",
                "action": "skipped"
            },
            {
                "name": "User1Pre84",
                "key": "user1pre84",
                "display_name": "User 1 Pre 84",
                "active": true,
                "deleted": false,
                "filter_error_message": "Is an active user.",
                "time_start": null,
                "time_finish": null,
                "time_duration": null,
                "anonymized_user_name": "",
                "anonymized_user_key": "",
                "anonymized_user_display_name": "",
                "action": "skipped"
            },
            {
                "name": "user-from-ad",
                "key": "JIRAUSER10400",
                "display_name": "User From AD",
                "active": false,
                "deleted": false,
                "filter_error_message": "There is at least one validation error message.",
                "time_start": null,
                "time_finish": null,
                "time_duration": null,
                "anonymized_user_name": "",
                "anonymized_user_key": "",
                "anonymized_user_display_name": "",
                "action": "skipped"
            }
        ]
    }

![](doc/images/example_2.png)

Let's discuss what the filters have done for each user to assess the result
of `filter_error_message`.

missplled-user:

The step "Get user-data from the Jira user REST-API" queries the user's data from
`GET /rest/api/2/user?includeDeleted=true&username=missplled-user`. It returns HTTP
status-code `404 Not Found`, and in the response there is the error-message
`"errorMessages": ["The user named 'missplled-user' does not exist"]`. Because the filter
follows the rule to only pass users it could find, it sets the
`"filter_error_message"`.

User1Pre84:

The step "Get user-data from the Jira user REST-API" queries the user's data from
`GET /rest/api/2/user?includeDeleted=true&username=User1Pre84`. It returns HTTP
status-code `200 OK`, and in the response there is the attribute `"active": true`. Because
the filter follows the rule to only pass inactive users, it sets the
`"filter_error_message"`.

user-from-ad:

The validation was queried from `GET /rest/api/2/user/anonymization?userKey=JIRAUSER10400`
, the HTTP-status-code is `400 Bad Request`, and the response is:

    {
        "errors": {
            "USER_NAME_CHANGE": {
                "errorMessages": [
                    "We can't rename users from external directories. Delete this user from the external directory and then sync it with Jira."
                ],
                "errors": {}
            },
            "USER_DISABLE": {
                "errorMessages": [
                    "We can't anonymize this user, because the directory that contains them is read-only."
                ],
                "errors": {}
            },
            "USER_EXTERNAL_ID_CHANGE": {
                "errorMessages": [
                    "We can't change the user ID for this user. Delete this user from the external directory and then sync it with Jira."
                ],
                "errors": {}
            }
        },
        "warnings": {},
        "expand": "affectedEntities",
        "userKey": "JIRAUSER10400",
        "userName": "user-from-ad",
        "displayName": "User From AD",
        "deleted": false,
        "email": "user-from-ad@example.com",
        "success": false,
        "operations": [
            "USER_NAME_CHANGE",
            "USER_KEY_CHANGE_PLUGIN_POINTS",
            "USER_KEY_CHANGE",
            "USER_DISABLE",
            "USER_TRANSFER_OWNERSHIP_PLUGIN_POINTS",
            "USER_NAME_CHANGE_PLUGIN_POINTS",
            "USER_ANONYMIZE_PLUGIN_POINTS",
            "USER_EXTERNAL_ID_CHANGE"
        ],
        "businessLogicValidationFailed": false
    }

This response is stored in the `report_details.json`. So if the Anonymizer reports
anything about a validation-error, search in that report by user-name or user-key.

## Command "anonymize"

### About

Anonymizing could be a long-running task for each user. The Anonymizer prints a
progress-percentage each minute. You can watch the progress also in the Jira admin-UI at
https://your-jira-url/secure/admin/user/AnonymizeUser!default.jspa

### Example 1: Anonymization without errors

We use this config-file `my_config.cfg`.

    [DEFAULT]
    jira_base_url = http://localhost:2990/jira
    jira_auth = Basic admin:admin
    user_list_file = users.cfg
    new_owner = the-new-owner
    # Speed up things a little bit (defaults are 10/3):
    initial_delay = 2
    regular_delay = 2

We use this user-list-file `users.cfg`:

    User1Pre84
    User2Pre84
    User1Post84
    User2Post84

All users are existent, inactive, and not connected to a read-only directory.
Users `User1Pre84` and `User1Post84` are no reporter or assignee in any issue.
User `User2Pre84` is assignee of issue EP-1, and `User2Post84`
is assignee of EP-2.

We call:

`python anonymize_jira_users.pyz anonymize -c my_config.cfg`

The output is:

    2021-04-05 18:34:05,514:INFO:read_users_from_user_list_file users.cfg
    2021-04-05 18:34:05,514:INFO:read_users_from_user_list_file found 4 users: ['User1Pre84', 'User2Pre84', 'User1Post84', 'User2Post84']
    2021-04-05 18:34:05,514:filter_by_duplicate 4 users
    2021-04-05 18:34:05,515:INFO:get_user_data for 4 users
    2021-04-05 18:34:05,628:INFO:filter_by_existance 4 users
    2021-04-05 18:34:05,628:INFO:filter_by_active_status 4 users:
    2021-04-05 18:34:05,628:INFO:get_anonymization_validation_data for 4 users
    2021-04-05 18:34:05,628:INFO:get_anonymization_validation_data for 'User1Pre84'
    2021-04-05 18:34:05,666:INFO:get_anonymization_validation_data for 'User2Pre84'
    2021-04-05 18:34:05,691:INFO:get_anonymization_validation_data for 'User1Post84'
    2021-04-05 18:34:05,716:INFO:get_anonymization_validation_data for 'User2Post84'
    2021-04-05 18:34:05,742:INFO:filter_by_validation_errors 4 users
    2021-04-05 18:34:05,742:INFO:filter_by_validation_errors has approved 4 of 4 users for anonymization: ['User1Pre84', 'User2Pre84', 'User1Post84', 'User2Post84']
    2021-04-05 18:34:05,768:INFO:is_any_anonymization_running ? No
    2021-04-05 18:34:05,768:INFO:anonymize_users starting anonymizing 4 users
    2021-04-05 18:34:05,768:INFO:anonymize_user #1 (name/key): User1Pre84/user1pre84
    2021-04-05 18:34:09,066:INFO:anonymize_user #2 (name/key): User2Pre84/user2pre84
    2021-04-05 18:34:12,167:INFO:anonymize_user #3 (name/key): User1Post84/JIRAUSER10301
    2021-04-05 18:34:15,249:INFO:anonymize_user #4 (name/key): User2Post84/JIRAUSER10302
    
    Result:
      Users in user-list-file: 4
      Skipped users: 0
      Anonymized user: 4
      Background re-index triggered: False

The `report.json` is:

    {
        "overview": {
            "number_of_users_in_user_list_file": 4,
            "number_of_skipped_users": 0,
            "number_of_anonymized_users": 4,
            "is_background_reindex_triggered": false
        },
        "users": [
            {
                "name": "User1Pre84",
                "key": "user1pre84",
                "display_name": "User 1 Pre 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": "2021-04-05T18:34:05.827+0200",
                "time_finish": "2021-04-05T18:34:07.496+0200",
                "time_duration": "00:01",
                "anonymized_user_name": "jirauser10103",
                "anonymized_user_key": "JIRAUSER10103",
                "anonymized_user_display_name": "user-57690",
                "action": "anonymized"
            },
            {
                "name": "User2Pre84",
                "key": "user2pre84",
                "display_name": "User 2 Pre 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": "2021-04-05T18:34:09.090+0200",
                "time_finish": "2021-04-05T18:34:09.235+0200",
                "time_duration": "00:01",
                "anonymized_user_name": "jirauser10104",
                "anonymized_user_key": "JIRAUSER10104",
                "anonymized_user_display_name": "user-2127b",
                "action": "anonymized"
            },
            {
                "name": "User1Post84",
                "key": "JIRAUSER10301",
                "display_name": "User 1 Post 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": "2021-04-05T18:34:12.190+0200",
                "time_finish": "2021-04-05T18:34:12.274+0200",
                "time_duration": "00:01",
                "anonymized_user_name": "jirauser10301",
                "anonymized_user_key": "JIRAUSER10301",
                "anonymized_user_display_name": "user-7b85e",
                "action": "anonymized"
            },
            {
                "name": "User2Post84",
                "key": "JIRAUSER10302",
                "display_name": "User 2 Post 84",
                "active": false,
                "deleted": false,
                "filter_error_message": "",
                "time_start": "2021-04-05T18:34:15.271+0200",
                "time_finish": "2021-04-05T18:34:15.353+0200",
                "time_duration": "00:01",
                "anonymized_user_name": "jirauser10302",
                "anonymized_user_key": "JIRAUSER10302",
                "anonymized_user_display_name": "user-faf6e",
                "action": "anonymized"
            }
        ]
    }

Beside the `report.json` the `report.csv` has been created and looks like the following
screenshot:

![](doc/images/example_3.png)

Let's discuss what the filters have done for each user to assess the result of the
anonymization-approval and what finally happened to the users.

user1pre84, user1post84:

The step "Get user-data from the Jira user REST-API" queries the user's data from
`GET /rest/api/2/user?includeDeleted=true&username=User1Pre84`. It returns HTTP
status-code `200 OK`, and in the response there is the attribute `"active": false`. The
validations-API returned no error. Because the filter follows the rule to only pass
existent, inactive users with no validation errors, no `filter_error_message`
has been set.

User2Pre84, User2Post84:

Similar the previous user, but they are assignees in one issue each. The fact these users
are assignees is no validation error as this will not prevent the anonymization.

`User2Pre84` was assignee of issue EP-1, and `User2Post84` was assignees of EP-2. We can
reverse check if the anonymized user-data in the report match the data in the issues:

The user-data in the following list are: User-name / user-key / display-name.

- EP-1:
    - Former assignee `User2Pre84 / User2Pre84 / User 2 Pre 84`
    - Current assignee `jirauser10104 / JIRAUSER10104 / user-2127b`
- EP-2
    - Former assignee `user2post84 / JIRAUSER10201 / User 2 Post 84`
    - Current assignee `jirauser10302 / JIRAUSER10302 / user-faf6e`

If you interested in more details, have a look at the atlassian-jira.log:

    2021-04-05 18:34:05,828+0200 JiraTaskExecutionThread-1 INFO admin 1114x73x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] User key is not anonymized (user1pre84), should anonymize to (JIRAUSER10103)
    2021-04-05 18:34:05,828+0200 JiraTaskExecutionThread-1 INFO admin 1114x73x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] Username is not anonymized (User1Pre84), should rename to (jirauser10103)
    ...
    2021-04-05 18:34:09,091+0200 JiraTaskExecutionThread-2 INFO admin 1114x76x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] User key is not anonymized (user2pre84), should anonymize to (JIRAUSER10104)
    2021-04-05 18:34:09,093+0200 JiraTaskExecutionThread-2 INFO admin 1114x76x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] Username is not anonymized (User2Pre84), should rename to (jirauser10104)
    ...
    2021-04-05 18:34:12,190+0200 JiraTaskExecutionThread-3 INFO admin 1114x79x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] User key is already anonymized (JIRAUSER10301), no need to change it
    2021-04-05 18:34:12,191+0200 JiraTaskExecutionThread-3 INFO admin 1114x79x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] Username is not anonymized (User1Post84), should rename to (jirauser10301)
    ...
    2021-04-05 18:34:15,271+0200 JiraTaskExecutionThread-4 INFO admin 1114x82x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] User key is already anonymized (JIRAUSER10302), no need to change it
    2021-04-05 18:34:15,272+0200 JiraTaskExecutionThread-4 INFO admin 1114x82x1 soc3mp 0:0:0:0:0:0:0:1 /rest/api/2/user/anonymization [c.a.j.user.anonymize.DefaultAnonymizeUserService] Username is not anonymized (User2Post84), should rename to (jirauser10302)   

Note about `User1Pre84` and `User2Pre84`:

The user-names as well as the user-keys were anonymized:

    User key is not anonymized (user1pre84), should anonymize to (JIRAUSER10103)
    Username is not anonymized (user1pre84), should rename to (jirauser10103)
    ...
    User key is not anonymized (user2pre84), should anonymize to (JIRAUSER10104)
    Username is not anonymized (User2Pre84), should rename to (jirauser10104)

Note about `User1Post84` and `User2Post84`:

Only the user-name were anonymized:

    User key is already anonymized (JIRAUSER10301), no need to change it
    Username is not anonymized (User1Post84), should rename to (jirauser10301)
    ...
    User key is already anonymized (JIRAUSER10302), no need to change it
    Username is not anonymized (User2Post84), should rename to (jirauser10302)

---

# Example-Workflow

This example comprises of:

1. Get a list of users as candidates for anonymization.
2. Assess and filter this list manually; create a new user-list with the remaining users
   to be anonymized.
3. Validate the users in that new user-list.
4. Anonymize the users in that new user-list.
5. Make a re-index, or let the Anonymizer trigger a re-index in step 4).

The example uses a directory-structure as follows:

    anonymizing
      anonymize_jira_users.pyz
      configs
        inst1_d.cfg                     # Config for the Jira dev-instance.
        inst1_p.cfg                     # Config for the Jira prod-instance.
      reports                           # The root-dir for all anonymization-runs
        <date>_<time>_<instance> *      # The dir for the current anonymization
          1_inactive_users       *      # Sub-dir for reports of command 'inactive-users'
          2_validate             *      # Sub-dir for reports of command 'validate'
          3_anonymize            *      # Sub-dir for reports of command 'anonymize'

The directories marked with * will be created by the Anonyizer.

The commands are:

    #
    # Prepare some env-vars:
    #
    export JIRA_INSTANCE=inst1_d
    export CONFIG_FILE=configs/${JIRA_INSTANCE}.cfg
    export REPORTS_BASE_DIR="reports/`date +%Y%m%d_%H%M%S_${JIRA_INSTANCE}`"

.

    #
    # 1. Let the Anonymizer create a list of users potentially to be anonymized. This 
    #   command creates the file inactive_users.cfg in the report-dir.
    #
    # First create the report dir. The Anonymizer creates this by itself, but it is
    # needed for the tee-command, which starts copying the Anonymizer's output before
    # the Anonymizer has created that directory.
    #
    mkdir -p $REPORTS_BASE_DIR/1_inactive_users
    python anonymize_jira_users.pyz inactive-users -c $CONFIG_FILE \
        --exclude-groups technical_users do_not_anonymize \
        -o $REPORTS_BASE_DIR/1_inactive_users 2>&1
        | tee $REPORTS_BASE_DIR/1_inactive_users/out.log

.

    #
    # 2. Assess and filter the users in inactive_users.cfg manually. Create a new 
    #   user-list inactive_users_assessed.cfg.
    #   ...
    #

.

    #
    # 3. Let the Anonymizer validate the users in assessed_inactive_users.cfg.
    #   Have a look at anonymizing_report.json/.csv afterwards.
    #
    mkdir -p $REPORTS_BASE_DIR/2_validate
    python anonymize_jira_users.pyz validate -c $CONFIG_FILE \
        -o $REPORTS_BASE_DIR/2_validate \
        -i $REPORTS_BASE_DIR/1_inactive_users/inactive_users_assessed.cfg 2>&1
        | tee $REPORTS_BASE_DIR/2_validate/out.log

.

    #
    # 4. Let the Anonymizer anonymize the users in assessed_inactive_users.cfg.
    #
    mkdir -p $REPORTS_BASE_DIR/3_anonymize
    python anonymize_jira_users.pyz anonymize -c $CONFIG_FILE \
        -o $REPORTS_BASE_DIR/3_anonymize \
        -i $REPORTS_BASE_DIR/1_inactive_users/inactive_users_assessed.cfg 2>&1
        | tee $REPORTS_BASE_DIR/3_anonymize/out.log

.

    #
    # 5. Make a re-index. You could let the Anonymizer do this by setting the option '-x'.
    #

---

# My Workflow

I maintain 3 Jira instances B, C, and O. Instance C is connected to a MS Active Directory,
and B and O have local user-management maintained by a specific department.

Instance C:

The workflow is according to the steps in "Example Workflow", but assessing the users is
supported by Python-script `assess_ad_users.py` located in the tools-directory.

I my company, employees going to leave will get an expire-date in the near future in AD.
Two weeks after that expire-date, the user is automatically removed from AD.

Employees who have left for parental leave, sabbatical leave, or other similar reasons
will return. These employees get a placeholder expire-date of e.g. 01.01.3000 and will be
kept in AD.

For anonymizing this means: If a Jira-user's account can't be found in AD, they definetely
have left the company and shall be anonymized.

The steps are:

1. Let the Anonymizer create a list of users potentially to be anonymized.
2. Assess the users:
    1. Call
       `python assess_ad_users.py %REPORTS_BASE_DIR%\1_inactive_users\inactive_users.cfg`
       . This will check each user for existance in AD. The script writes the new
       file `inactive_users_assessed.cfg`. This file is basically `inactive_users.cfg`.
       But it is extended with data from AD. If a user is still in AD, the user is
       commented out.
    2. Assess the users manually afterwards. Mayby you know something about them. E.g. if
       they have new AD-accounts and they have filters or dashboards thay want to switch
       from the former account to the new one, and so forth.
3. Let the Anonymizer validate the users in inactive_users_assessed.cfg.
4. Let the Anonymizer anonymize the users in assessed_inactive_users.cfg.
5. Archive the data of the anonymized users: The mapping of the user-name to the
   anonymized user-name/key and -display-name is archived for legal- and revision-
   department. This is done on a restricted Confluence page. To put the data in the page,
   the report.csv is imported to a MS Excel sheet, and copied from there to the page (this
   is the only way I know to let Confluence detect the 'table format').

Instance B and O:

As instance C, but with a different step 2:

Assess the users: Send the list to the department responsible for the user-management and
let them comment out users to not anoymize.

---

# Anonymize deleted users

Deleted users aren't anymore in DB table `cwd_user`, but still in table `app_user`.

Anonymized users have a lower_user_name of format jirauser12345.

The following SQL statement gets the user-names of deleted, not yet anonymized users:

    SELECT au.lower_user_name 
    FROM   app_user au 
    WHERE  au.lower_user_name NOT LIKE 'jirauser%' 
    AND au.lower_user_name NOT IN (SELECT u.lower_user_name 
                                   FROM   cwd_user u) 

Put these users in the user_list_file.cfg and run the anonymization.

---

# History of anonymization and related functions

**Jira 8.7, released 3 February 2020:**

- Described by JRASERVER-70501 "Anonymize use activity news"
- Anonymization in UI and REST API.
- Allows anonymization of present as well as deleted users:
  "You can anonymize users in two ways — the choice here depends on whether the user is
  still active, or has been deleted." [1].
- Limitations: "Personal data might still appear in the issue history, which shows all
  past activity on an issue." [1].

Remark: I can't get anonymization of deleted users running in Jira versions before 8.10,
neither in the admin-UI nor with the REST-API. The anonymization-dialog shows:
_The user named 'jojo' does not exist_.

**Jira 8.8, released 19 March 2020**

- Audit log improvements for developers [2].
- Support of a new auditing REST-API.

**Jira 8.10, released 23 June 2020**

- [3]: Extended the scope of anonymization to include the following items. If you have
  already anonymized some users, you can anonymize them again, in which case we’ll take
  care of the newly supported items and make your users disappear in a puff of GDPR. The
  items are:
    - Reporters and creators of issue collectors
    - Full name in the issue history (Assignee, Reporter, Single- and Multi-user picker
      fields)
    - Ability to anonymize users that have already been deleted

**Jira 8.12, released 26 August 2020**

- Fixed:
  [JRASERVER-71153 Usernames not fully anonymized in issue history](https://jira.atlassian.com/browse/JRASERVER-71153)
- REST-API GET /rest/api/2/user supports 'includeDeleted'.
- REST-API deprecated: GET /rest/api/2/auditing/record [5]

**References:**

- [1] [Preparing for Jira 8.7 | GDPR: Anonymizing users](https://confluence.atlassian.com/jiracore/gdpr-anonymizing-users-983503046.html)
- [2] [Audit log improvements for developers](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html)
- [3] [Jira Software 8.10.x release notes | User anonymization (GDPR) improvements](https://confluence.atlassian.com/jirasoftware/jira-software-8-10-x-release-notes-1004948108.html#JiraSoftware8.10.xreleasenotes-gdpr)
- [4] [REST API GET /rest/api/2/auditing/record](https://docs.atlassian.com/software/jira/docs/api/REST/8.10.0/#api/2/user-getUser)
- [5] [GET /rest/api/2/auditing/record deprecated](https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords)

---

# F. A. Q.

## Can we Anonymize a user on JIRA Cloud?

No,
see [Can we Anonymize a user on JIRA Cloud?](https://community.atlassian.com/t5/Atlassian-Access-questions/Can-we-Anonymize-a-user-on-JIRA-Cloud/qaq-p/1632822)

---

# Known issues

## Command inactive-users might return a max. of 1000 users

The command `inactive-users` uses the REST API `/rest/api/2/user/search`. There is an open
Jira-bug documented in
[JRASERVER-29069](https://jira.atlassian.com/browse/JRASERVER-29069) which leads
(in some Jira instances) to a max. of 1000 users. I have seen this bug in some instances,
but others delivered more than 1000 users. I have no idea under what circumstances this
bug occurs or not.

If the list of users in the out-file of command `inactive-users` is exact 1000, it is
likely you ran into the bug. The Anonymizer logs a warning to the command line in that
case.

The anonymizer calls the API with following parameters:

`/rest/api/2/user/search?username=.&includeInactive=true&includeActive=false&startAt=...`

Unfortunately the REST API itself hasn't an exclude-parameter, so the amount of users will
grow over time (the users anonymized so far still counts to the users the API delivers).

## Validation error-messages in unexpected language

The returned error-messages in the JSON-responses
from [Jira Anonymization REST API](https://docs.atlassian.com/software/jira/docs/api/REST/8.14.1/#api/2/user/anonymization)
I expect in the language-setting of the executing admin. But they're sometimes in a
different language. Is this different language the system default language, or the one of
the user to be anonymized? Or...?

## Anonymization slow in case Jira is connected to an Oracle-DB

- [JRASERVER-71251 Improve User Anonymize Feature](https://jira.atlassian.com/browse/JRASERVER-71251)

## Tickets at Atlassian

- [JSDSERVER-6886 Allow bulk-nonymizing users](https://jira.atlassian.com/browse/JSDSERVER-6886)
- [JSDSERVER-6881 During the anonymization steps, Jira should additional display the future anonymized user name](https://jira.atlassian.com/browse/JSDSERVER-6881)
- [JRASERVER-71251 Improve User Anonymize Feature](https://jira.atlassian.com/browse/JRASERVER-71251)

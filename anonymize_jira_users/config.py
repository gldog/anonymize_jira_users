import argparse
import configparser
import locale
import logging
import os
import pathlib
import re
import sys
import textwrap
from dataclasses import dataclass, field
from logging import Logger

__version__ = '1.0.0.dev'


# This is not a valid Python-version, but who cares.
# __version__ = '1.0.0-SNAPSHOT'


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


@dataclass()
class Config:
    #
    # Constants
    #
    INACTIVE_USERS_CMD = 'inactive-users'
    ANONYMIZE_CMD = 'anonymize'
    # The validate-command is a subset of the anonymize-command. They share a lot of code and
    # the "anonymization"-reports.
    VALIDATE_CMD = 'validate'
    MISC_CMD = 'misc'
    LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    PRETTY_PRINT_LOG_LEVELS = ', '.join(LOG_LEVELS)
    # These values for false and true are taken from the docs of Python
    # configParser.getboolean(). They are also given in configparser.py
    # But in configParser, there are also values 0 for false and 1 for true described.
    # But the Anonymizer allows integers as values, which shall not be interpreted as
    # booleans. Therefore 0 and 1 are ignored as booleans here.
    BOOLEAN_FALSE_VALUES = ['no', 'false', 'off']
    BOOLEAN_TRUE_VALUES = ['yes', 'true', 'on']

    DEFAULT_CONFIG = {
        # The subparser-name as a default of None is technically not needed. But it is useful to
        # place this dict-entry at the top-position at option --info.
        'subparser_name': None,
        'jira_base_url': '',
        'jira_auth': '',
        'exclude_groups': [],
        'user_list_file': '',
        'encoding': None,
        'report_out_dir': '.',
        'loglevel': 'INFO',
        'is_expand_validation_with_affected_entities': False,
        'new_owner': '',
        'initial_delay': 10,
        'regular_delay': 3,
        'timeout': 0,
        'is_trigger_background_reindex': False,
    }

    REPORT_BASENAME = 'anonymizing_report'
    TEMPLATE_FILENAME = 'my_bare_default_config.cfg'
    INACTIVE_USERS_OUTFILE = 'inactive_users.cfg'

    #
    # The Attributes
    #
    effective_config: dict = field(default=None, init=False)
    log: Logger = field(default=None, init=False)
    script_name: str = field(default=os.path.basename(__file__), init=False)
    args: argparse.Namespace = field(init=False)
    # iva means Inactive users, Anonymize, Validate.
    iva_parent_parser: argparse.ArgumentParser = field(init=False)
    anonymize_subparser: argparse.ArgumentParser = field(init=False)
    inactive_users_subparser: argparse.ArgumentParser = field(init=False)
    misc_subparser: argparse.ArgumentParser = field(init=False)

    def __post_init__(self):
        self.effective_config = self.DEFAULT_CONFIG.copy()
        self.effective_config['report_details_filename'] = self.REPORT_BASENAME + '_details.json'
        self.effective_config['report_json_filename'] = self.REPORT_BASENAME + '.json'
        self.effective_config['report_text_filename'] = self.REPORT_BASENAME + '.csv'
        self.parser = self.init_parser_and_parse_parameters()
        self.args = self.parser.parse_args()

        # Make the effective config from a) the default-config, b) the config-file if given, and c) the
        # command-line-parameters. This is not needed for command CMD_MISC. But to not make an exception here, always
        # make it.
        self.make_effective_config(self.args)

        # After creation of effective_config:
        self.configure_logging()

        # Print help if no argument is given.
        # sys.argv at least contains the script-name, so it has at least the length of 1.
        if len(sys.argv) == 1:
            self.parser.print_help()
            sys.exit(0)

    def init_parser_and_parse_parameters(self):
        #
        # Part 1: Define the arguments.
        #
        # All actions with 'store_true' must have a default=None. This is important for the configuration chaining of
        # the DEFAULT_CONFIG, the config-file, and the args.
        #
        self.epilog = textwrap.dedent(f"""\
        How to start

        o Create the file usernames.txt with the user-names to be anonymized, one 
          user-name per line.
        o Create a config-file-template:
              {self.script_name} misc -g
          The file my_bare_default_config.cfg has been created.
        o Rename the file, e.g. to my_config.cfg.
        o In that file, set the attributes jira_base_url, jira_auth with
          format 'Basic admin:admin', user_list_file = usernames.txt, new_owner.
        o Call
              {self.script_name} validate -c my_config.cfg
          to see what would happen in case of anonymizing.
        o Call
              {self.script_name} anonymize -c my_config.cfg
          to execute anonyization.
        o Have a look at the report {self.effective_config['report_text_filename']}. More details 
          about the users are given in {self.effective_config['report_details_filename']}.
        """)
        parser = \
            argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                    description="The Anonymizer is a Python3-script to help"
                                                " Jira-admins anonymizing Jira-users in bulk.",
                                    epilog=self.epilog)
        parser.add_argument('--version',
                            action='version',
                            version=f'%(prog)s {__version__}')

        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('-l', '--loglevel',
                                   choices=self.LOG_LEVELS,
                                   help="Log-level."
                                        f" Defaults to {self.DEFAULT_CONFIG['loglevel']}.")

        #
        # Arguments common to 'anonymize', 'inactive-users', and 'validate'.
        #
        self.iva_parent_parser = argparse.ArgumentParser(add_help=False)
        self.iva_parent_parser.add_argument('-c', '--config-file',
                                            help="Config-file to pre-set command-line-options."
                                                 " You can generate a config-file-template with"
                                                 " option 'misc -g'. There are parameters in the"
                                                 " config-file not present on the command line."
                                                 " Empty parameters in the config-file are ignored."
                                                 " Parameters given on the command line overwrite"
                                                 " parameters given in the config-file.")
        self.iva_parent_parser.add_argument('-b', '--jira-base-url',
                                            help="Jira base-URL.")
        self.iva_parent_parser.add_argument('-a', '--jira-auth',
                                            metavar='ADMIN_USER_AUTH',
                                            help="Admin user-authentication."
                                                 " Two auth-types are supported: Basic, and"
                                                 " Bearer (starting with Jira 8.14). The format for"
                                                 " Basic is: 'Basic <user>:<pass>'. The format for"
                                                 " Bearer is: 'Bearer <token>'.")
        self.iva_parent_parser.add_argument('-o', '--report-out-dir',
                                            action=PathAction,
                                            help="Output-directory to write the reports into."
                                                 " If it doesn't exist, it'll be created."
                                                 " If you'd like the date included,"
                                                 " give something like"
                                                 " `date +%%Y%%m%%d-%%H%%M%%S-anonymize-instance1`."
                                                 " Defaults to"
                                                 f" '{self.DEFAULT_CONFIG['report_out_dir']}'.")

        post_iva_parent_parser = argparse.ArgumentParser(add_help=False)
        post_iva_parent_parser.add_argument('--info',
                                            action='store_true',
                                            default=None,
                                            help="Print the effective config, and the"
                                                 " character-encoding Python suggests, then exit.")

        #
        # Arguments common to 'anonymize' and 'validate'.
        #
        va_parent_parser = argparse.ArgumentParser(add_help=False)
        va_parent_parser.add_argument('-i', '--user-list-file',
                                      help="File with user-names to anonymize or just to validate."
                                           " One user-name per line. Comments are allowed:"
                                           " They must be prefixed by '#' and they must appear on"
                                           " their own line. The character-encoding is platform"
                                           " dependent Python suggests. If you have trouble with"
                                           " the encoding, try out the parameter '--encoding'.")
        va_parent_parser.add_argument('--encoding',
                                      metavar='ENCODING',
                                      help="Force a character-encoding for reading the"
                                           " user-list-file. Empty means platform dependent Python"
                                           " suggests. If you run on Win or the user-list-file was"
                                           " created on Win, try out one of these encodings: utf-8,"
                                           "  cp1252, latin1.")
        va_parent_parser.add_argument('--expand-validation-with-affected-entities',
                                      action='store_true',
                                      default=None,
                                      dest='is_expand_validation_with_affected_entities',
                                      help="Include 'affectedEntities' in the validation result."
                                           " This is only for documentation to enrich the detailed"
                                           " report. It doesn't affect the anonymization."
                                           " Doing so could increase significantly execution time.")

        sp = parser.add_subparsers(dest='subparser_name')

        self.inactive_users_subparser = sp.add_parser(self.INACTIVE_USERS_CMD,
                                                      parents=[parent_parser,
                                                               self.iva_parent_parser,
                                                               post_iva_parent_parser],
                                                      help="Retrieves a list of inactive, not yet"
                                                           " anonymized users. These users are"
                                                           " candidates for anonymization.")
        self.inactive_users_subparser.add_argument('-G', '--exclude-groups',
                                                   nargs='+',
                                                   help="Exclude members of these groups."
                                                        " Multiple groups must be space-separated."
                                                        " If a group contains spaces, the group"
                                                        " must be enclosed in single or double."
                                                        " quotes")
        validate_sp = sp.add_parser(self.VALIDATE_CMD,
                                    parents=[parent_parser,
                                             self.iva_parent_parser,
                                             va_parent_parser,
                                             post_iva_parent_parser],
                                    help="Validates user anonymization process.")
        self.anonymize_subparser = sp.add_parser(self.ANONYMIZE_CMD,
                                                 parents=[parent_parser,
                                                          self.iva_parent_parser,
                                                          va_parent_parser,
                                                          post_iva_parent_parser],
                                                 help="Anonymizes users.")
        self.misc_subparser = sp.add_parser(self.MISC_CMD,
                                            parents=[parent_parser],
                                            help="Intended to bundle diverse functions."
                                                 " Currently `-g` to generate a"
                                                 " template-config-file is the only function.")

        #
        # Add arguments special to command "anonymize".
        #
        self.anonymize_subparser.add_argument('-n', '--new-owner',
                                              help="Transfer roles of all anonymized users to the"
                                                   " user with this user-name.")
        self.anonymize_subparser.add_argument('-x', '--background-reindex',
                                              action='store_true',
                                              default=None,
                                              dest='is_trigger_background_reindex',
                                              help="If at least one user was anonymized, trigger a"
                                                   " background re-index.")

        #
        # Add arguments special to command "misc".
        #
        self.misc_subparser.add_argument('-g', '--generate-config-template',
                                         metavar='CONFIG_TEMPLATE_FILE',
                                         const=self.TEMPLATE_FILENAME,
                                         nargs='?',
                                         dest='config_template_filename',
                                         help="Generate a configuration-template."
                                              f" Defaults to {self.TEMPLATE_FILENAME}.")

        #
        # Part 2: Parse the arguments and return them.
        #
        return parser

    def make_effective_config(self, args):
        """Make the effective config from a) the default-config, b) the config-file if given, and c) the
        command-line-parameters.

        The values within a ConfigParser are always strings. After a merge with a Python dict, the expected types could
        be gone. E.g. if a boolean is expected, but the ConfigParser delivers the string "false", this string is
        True. This function converts all read parameters to Python-types.

        :param args: The arguments got from the command-line.
        :return: Nothing.
        """

        # If a config-file is given, merge it into the global config. No-None-values overwrites the values present
        # so far.
        #
        # A config-file can only be present for the sub-parsers CMD_ANONYMIZE, CMD_INACTIVE_USERS, CMD_VALIDATE,
        # but not for CMD_MISC. But to not make the CMD_MISC an exception, always note the config_file. Doing this,
        # we have to check if the config_file attribute is giben in the namespace (it is absent in case of CMD_MISC).
        if hasattr(args, 'config_file') and args.config_file:
            parser = configparser.ConfigParser()
            # The parser could read the file by itself by calling parser.read(args.config_file). But if the file doesn't
            # exist, the parser uses an empty dict silently. The open() is to throw an error in case the file can't be
            # opened.
            with open(args.config_file) as f:
                parser.read_file(f)
            # Values from the [DEFAULTS] section. Only this section is used by the Anonymizer.
            defaults_section = parser.defaults()

            configfile_config = {}
            # parser.defaults() is documented as dict, but it is something weird without an .items()-function.
            # Wrapping it by a dict() function solves this.
            for k, v in dict(defaults_section).items():
                if k.lower() == 'exclude_groups':
                    groups = re.split('[\\n\\r]+', v)
                    configfile_config[k] = groups
                elif v.lower() in self.BOOLEAN_TRUE_VALUES:
                    configfile_config[k] = True
                elif v.lower() in self.BOOLEAN_FALSE_VALUES:
                    configfile_config[k] = False
                else:
                    try:
                        configfile_config[k] = int(v)
                    except ValueError:
                        # This value must be a string-value, because other types are processed so far.
                        # Take it only if not empty. This is important because merge_dicts() ignores only None-values,
                        # but takes into account empty strings. The ConfigParser delivers empty strings for not-set
                        # values, e. g.
                        #   loglevel =
                        # is equal to
                        #   loglevel = ''
                        # But because loglevel is not None, the value '' would overwrite the default-value INFO. As as
                        # result, the loglevel wouldn't be set at all and would lead to an error in set_loglevel().
                        # The loglevel is only an example. This would become a problem for several attributes.
                        if v:
                            configfile_config[k] = v

            self.merge_dicts(self.effective_config, configfile_config)

        # Merge the config-file-parameters and the command-line-arguments in and over the global config. No-None-values
        # overwrites the values present so far.
        self.merge_dicts(self.effective_config, vars(args))

        self.effective_config['locale_getpreferredencoding'] = f'{locale.getpreferredencoding()}'
        self.effective_config['sys_getfilesystemencoding'] = f'{sys.getfilesystemencoding()}'

    @property
    def sanitized_effective_config(self) -> dict:
        sanitized_effective_config = self.effective_config.copy()
        sanitized_effective_config['jira_auth'] = '<sanitized>'
        return sanitized_effective_config

    @staticmethod
    def merge_dicts(d1: dict, d2: dict):
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

    def configure_logging(self):
        self.log = logging.getLogger()
        # Set basicConfig() to get levels less than WARNING running in our logger.
        # See https://stackoverflow.com/questions/56799138/python-logger-not-printing-info
        logging.basicConfig(level=logging.WARNING)
        # Set a useful logging-format. Not the most elegant way, but it works.
        self.log.handlers[0].setFormatter(
            # logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s(): %(message)s'))
            logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s %(message)s'))
        # See also https://docs.python.org/3/howto/logging.html:
        numeric_level = self.effective_config.get('loglevel')
        # The check for valid values have been done in parser.add_argument().
        self.log.setLevel(numeric_level)
        # Adjust logging-level of module "urllib3". If our logging is set to DEBUG, that also logs in that level.
        logging.getLogger('urllib3').setLevel(logging.WARNING)

    def write_config_template_file(self):
        with open(self.args.config_template_filename, 'w') as f:
            help_text = f"""\
            ####
            #
            # Configuration template for {os.path.basename(__file__)}
            #
            # General:
            #   - These values are true in any notation: {self.BOOLEAN_TRUE_VALUES}.
            #   - These values are false in any notation: {self.BOOLEAN_FALSE_VALUES}.
            #
            ####

            [DEFAULT]

            #   Loglevel. Valid levels are {self.PRETTY_PRINT_LOG_LEVELS}.
            #   The given value is the default.
            #loglevel = {self.DEFAULT_CONFIG}
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
            #report_out_dir = {self.DEFAULT_CONFIG}
            #   Include 'affectedEntities' in the validation result. This is only for documentation 
            #   to enrich the detailed report. It doesn't affect the anonymization.
            #   Doing so could increase significantly execution time.
            #   The given value is the default.
            #is_expand_validation_with_affected_entities = {self.DEFAULT_CONFIG}
            #   Transfer roles to the user with this user-name.
            #   The given value is an example.
            #new_owner = new-owner
            #   Initial delay in seconds the Anonymizer waits after the anonymization is
            #   triggered and the first call to get the anonymization-progress.
            #   The default of Jira is {self.DEFAULT_CONFIG} seconds, and this is also the default of the Anonymizer.
            #initial_delay = {self.DEFAULT_CONFIG}
            #   The delay in seconds between calls to get the anonymization-progress.
            #   The default of Jira is {self.DEFAULT_CONFIG} seconds, and this is also the default of the Anonymizer.
            #regular_delay = {self.DEFAULT_CONFIG}
            #   Time in seconds the anonymization shall wait to be finished.
            #   0 (or any negative value) means: Wait as long as it takes.
            #   The given value is the default.
            #timeout = {self.DEFAULT_CONFIG}
            #   If at least one user was anonymized, trigger a background re-index.
            #   The given value is the default.
            #is_trigger_background_reindex = {self.DEFAULT_CONFIG}
            """
            f.write(textwrap.dedent(help_text))

    def create_report_dir(self):
        report_dirpath = pathlib.Path(self.effective_config['report_out_dir'])
        report_dirpath.mkdir(parents=True, exist_ok=True)
        return report_dirpath

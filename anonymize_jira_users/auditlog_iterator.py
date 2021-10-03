import itertools
import time
from dataclasses import dataclass, field
from logging import Logger

from execution_logger import ExecutionLogger
from jira import Jira


@dataclass
class AuditLogIterator:
    """Chose one of two audit-log-APIs and iterate over the pages and page-entries.

    Use either the deprecated audit-records API or the newer audit-events API.
    The switch use_deprecated_records_api delegates calls to one of these audit REST-APIs.

    Atlassian introduced anonymization in Jira 8.7.
    The Anonymizer queries the anonymized user-data from the audit-log.

    Jira supports two auditing REST-APIs:

    1. GET /rest/api/2/auditing/record, deprecated since 8.12 (the older one).
        https://docs.atlassian.com/software/jira/docs/api/REST/8.12.0/#api/2/auditing-getRecords
    2. "Audit log improvements for developers", introduced in 8.8 (the newer one).
        https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html
    """
    log: Logger
    jira: Jira
    execution_logger: ExecutionLogger
    user_logger_rest_auditing: dict
    start_time: str
    finish_time: str
    use_deprecated_records_api: bool = field(default=False)

    start_time_utc: str = field(init=False)
    finish_time_utc: str = field(init=False)
    current_page_num: int = field(init=False, default=0)

    JIRA_DEFAULT_LIMIT_PER_PAGE = 1000

    def __post_init__(self):
        self.start_time_utc = self.date_str_to_utc_str(self.start_time)
        self.finish_time_utc = self.date_str_to_utc_str(self.finish_time)
        self.execution_logger.logs['auditlog_iterator'] = {'doc': "The date in the URL-param is UTC."}

    @staticmethod
    def date_str_to_utc_str(date_str):
        """Convert date/time-string of format "2020-12-29T23:17:35.399+0100" to UTC in format
        2020-12-29T23:16:35.399Z.

        :param date_str: Expect format "2020-12-29T23:17:35.399+0100"
        :return: String UTC in format 2020-12-29T23:16:35.399Z
        """
        # Split string in "2020-12-29T23:17:35" and ".399+0100".
        date_parts = date_str.split('.')
        # Convert to UTC. The conversion respects DST.
        date_utc = time.strftime("%Y-%m-%dT%H:%M:%S",
                                 time.gmtime(time.mktime(time.strptime(date_parts[0],
                                                                       '%Y-%m-%dT%H:%M:%S'))))
        date_utc += f'.{date_parts[1][:3]}Z'
        return date_utc

    def get_audit_records(self, from_time_utc, to_time_utc, offset):
        rel_url = '/rest/api/2/auditing/record'
        url = self.jira.base_url + rel_url
        url_params = {'from': from_time_utc, 'to': to_time_utc, 'offset': offset}
        r = self.jira.session.get(url=url, params=url_params)
        r.raise_for_status()
        return r

    def get_audit_events(self, from_time_utc, to_time_utc):
        rel_url = '/rest/auditing/1.0/events'
        url = self.jira.base_url + rel_url
        url_params = {'from': from_time_utc, 'to': to_time_utc}
        r = self.jira.session.get(url=url, params=url_params)
        r.raise_for_status()
        return r

    def pages_from_audit_records_api(self):
        self.current_page_num = -1
        for offset in itertools.count(start=0, step=self.JIRA_DEFAULT_LIMIT_PER_PAGE):
            r = self.get_audit_records(self.start_time_utc, self.finish_time_utc, offset)
            self.current_page_num += 1
            self.execution_logger.logs['auditlog_iterator'].update({'current_page': Jira.serialize_response(r)})
            r.raise_for_status()
            records = r.json()['records']
            yield records
            if len(records) < self.JIRA_DEFAULT_LIMIT_PER_PAGE:
                break
            offset += self.JIRA_DEFAULT_LIMIT_PER_PAGE

    def pages_from_audit_events_api(self):
        r = self.get_audit_events(self.start_time_utc, self.finish_time_utc)
        self.current_page_num = 0
        self.execution_logger.logs['auditlog_iterator'].update({'current_page': Jira.serialize_response(r)})
        r.raise_for_status()
        yield r.json()['entities']
        while not r.json()['pagingInfo']['lastPage']:
            r = self.jira.session.get(r.json()['pagingInfo']['nextPageLink'])
            self.current_page_num += 1
            self.execution_logger.logs['auditlog_iterator'].update({'current_page': Jira.serialize_response(r)})
            r.raise_for_status()
            yield r.json()['entities']

    def entries(self):
        if self.use_deprecated_records_api:
            pages = self.pages_from_audit_records_api()
        else:
            pages = self.pages_from_audit_events_api()

        for page in pages:
            for entry in page:
                yield entry

    def __iter__(self):
        return self.entries()

    def get_current_page(self):
        return {self.current_page_num: self.execution_logger.logs['auditlog_iterator']['current_page'].copy()}

    def clear_current_page(self):
        self.execution_logger.logs['auditlog_iterator']['current_page'] = None

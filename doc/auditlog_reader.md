auditlog_reader
=

# General

This is to explain how the module auditlog_reader.py works.

Atlassian introduced anonymization in Jira 8.7.

Jira supports two auditing REST-APIs:

* [GET /rest/api/2/auditing/record](https://docs.atlassian.com/software/jira/docs/api/REST/8.0.0/#api/2/auditing-getRecords)
  , deprecated since 8.12.
* GET /rest/auditing/1.0/events, introduced in 8.8,
  see [Audit log improvements for developers](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html)
  .

The Anonymizer uses the API 1) for Jira-versions 8.7 to 8.9, and API 2) since Jira-versions 8.10.

Why is Jira 8.10 the border?

* In the API 1) /rest/api/2/auditing/record until 8.9 the summary is always in EN.
* In the API 2) /rest/auditing/1.0/events since 8.10 the i18n-keys can be used to identify events.

The details in the responses depends on:

* Jira-version
* System default language at anonymization.
* Languange setting at the time of the request of the anonymizing admin.
* Jira-version the anonymized user was created: <8.4 or >=8.4.
* Jira user-name format: If the username looks like an anonymized user like jirauser12345 or not.
  In case the user-name is of format username12345, the user-name and the user-key won't be anonymized.
  It seems Jira "thinks" those user has been anonymized.
* If the user was already anonymized.

For more details see auditlog_reader.py.

The user-data in the audit-log itself won't be anonymized.

# Articles and links

In Jira 8.7, Atlassian introduced user anonymization:
[Jira Core 8.7.x release notes | Anonymizing users for GDPR compliance](https://confluence.atlassian.com/jiracore/jira-core-8-7-x-release-notes-990550456.html)

In 8.10, Atlassian added the ability to anonymize users that have already been deleted:
[Jira Core 8.10.x release notes](https://confluence.atlassian.com/jiracore/jira-core-8-10-x-release-notes-1005343732.html#JiraCore8.10.xreleasenotes-gdpr)

[Auditing in Jira](https://confluence.atlassian.com/adminjiraserver/auditing-in-jira-938847740.html#AuditinginJira-AuditingandtheRESTAPI)

[Audit log events in Jira](https://confluence.atlassian.com/adminjiraserver/audit-log-events-in-jira-998879036.html)

[JRASERVER-71281 API Documentation for 8.9.1 for auditing records should be updated](https://jira.atlassian.com/browse/JRASERVER-71281):

> However the rest point "/rest/auditing/1.0/events" works well and we are able to retrieve the results. So there is a
> need to update the API reference documentation for 8.9.1 with latest working rest end point. The older version "
> /rest/api/2/auditing/record" should be mentioned as deprecated.


[Migrating to the new Jira audit log Java API](https://developer.atlassian.com/server/jira/platform/migrating-to-new-jira-audit-log-java-api/):

> In Jira 8.8 we announced the new and improved auditing feature which came with its own API.

[Improvements to your Jira 8.8 audit log](https://blog.developer.atlassian.com/improvements-to-your-jira-8-8-audit-log):

> Jira 8.8 Server and Data Center introduced a number of important changes to the audit log

> [=> Audit log improvements for developers (REST API)](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html)

> [=> NIST Special Publication 800-53 (Rev. 4)](https://nvd.nist.gov/800-53/Rev4/control/AU-3)

# Anonymized user data

The Anonymizer reads the following data from the audit-log-APIs:

* anonymized user-name
* anonymized user-key
* anonymized user-display-name

# About the user-key

Before Jira 8.4, the user-key is like the lowercase user-name.
Since Jira 8.4, the user-key is of format JIRAUSER12345.

# API 1): GET /rest/api/2/auditing/record

Deprecated since 8.12.

Doc: [GET /rest/api/2/auditing/record](https://docs.atlassian.com/software/jira/docs/api/REST/8.0.0/#api/2/auditing-getRecords)

The records after an anonymization are (in the order as present in the API):

1. record.summary: "User anonymized"
2. record.summary: "User renamed". E.g. "User1Pre84" / "jirauser10103".
3. record.summary: "User's key changed". E.g. "user1pre84" / "JIRAUSER10103".
4. record.summary: "User updated".
   Contains the user-display-name and email-address before/after.
   E.g. user-display-name "User 1 Pre 84" / "user-57690",
   email-address "User1Pre84@example.com" / "JIRAUSER10103@jira.invalid".
5. record.summary: "User anonymization started"

This is the full list of records.
But if a user has been created since Jira 8.4, the user-key is already of format JIRAUSER12345 and won't be anonymized.
As a result, anonymizing is lacking the records 3) `record.summary: "User's key changed"`.

The Anonymizer reads the anonymized user-name, user-key, and user-display-name from some of these records:

* The user-name and user-key from the record identified by record 1) `record.summary: "User anonymized"`.
* The user-display-name from the record identified by record 4) `record.summary: "User updated"`.

Jira allows anonymizing an already anonymized user.
In that case only recoreds 1) und 5) are present.

**TODO more details.**:
A special case is anonymizing a user that looks like an anonymized user.
E.g. the user with name jirauser12345.

The record-details depends on the Jira-version:

Until 8.9, the summary is always in EN:
`"summary": "User anonymized"`.
Starting with 8.10, the summary depends on the system default language.
E.g. if the setting is DE, the summary is:
`"summary": "Benutzer anonymisiert"`.

This means the relevant records can be identified until Jira-version 8.9

# API 2): GET /rest/auditing/1.0/events

introduced in 8.8

Doc: [Audit log improvements for developers](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-990552469.html)

The records after an anonymization are (in the order as present in the API):

1. type.actionI18nKey: "jira.auditing.user.anonymized"
2. type.actionI18nKey: "jira.auditing.user.renamed"
3. type.actionI18nKey: "jira.auditing.user.key.changed"
4. type.actionI18nKey: "jira.auditing.user.updated"
5. type.actionI18nKey: "jira.auditing.user.anonymization.started"

This is the full list of records.
But if a user has been created since Jira 8.4, the user-key is already of format JIRAUSER12345 and won't be anonymized.
As a result, anonymizing is lacking the records 3) `type.actionI18nKey: "jira.auditing.user.key.changed"`.

The Anonymizer reads the anonymized user-name, user-key, and user-display-name from some of these records:

* The user-name and user-key from the record identified by event
    1) `type.actionI18nKey: "jira.auditing.user.anonymized"`.
* The user-display-name from the record identified by event `type.actionI18nKey: "jira.auditing.user.updated"`.

Evolved over time. The event-details depends on the Jira-version.
But it is possible to use this API since Jira 8.10

# About user-names and user-keys

In Jira pre-6.0, Jira had only the user-name as an external and internal representation of a
user. This user-name couldn't be changed. In Jira 6.0 Atlassian introduced the distinction
between the user-name and the user-key. By this, the user-name could be changed; users
could be renamed, whereas the internal representation keeps unchanged.

From the Atlassian
docs [Renamable Users in JIRA 6.0](https://developer.atlassian.com/server/jira/platform/renamable-users-in-jira-6-0/)

> Introducing the user key
> Previously the username field was used both as a display value and also stored as the primary key of the user.
> In order to allow usernames to be changed, we obviously need a separate identifier field that is unchangeable.
>
>We have introduced a new field called "key" to users that is a case-sensitive String and will never change (also
> referred to as the "userkey").
> In order to correctly support systems with multiple directories, this key is applicable at the application level, not
> at
> the user directory level.
>
>Existing users will get allocated a key that is equal to the lowercase of the username.
> This means there is no need to migrate existing data: the stored value is the user key and even if the user's username
> is later edited, this stored key will remain correct.
(This assumes that you are already lower-casing the stored usernames which was required in order to avoid
> case-sensitivity bugs).

Since then, user-information is given in two DB-tables: The user-name is given in DB-table
`cwd_user` as `cwd_user.user_name` and `cwd_user.lower_user_name`, whereas the user-key is
given in the new DB-table `app_user` in `app_user.user_key`. The relation between them is
`cwd_user.lower_user_name = app_user.lower_user_name`.

The Anonymization REST API takes the user-key. This is in contrast to the admin-UI, which
takes the user-name. Giving the user-name is convenient, as the user-key is not obvious and
have to be queried, e. g. by
REST [GET /rest/api/2/user](https://docs.atlassian.com/software/jira/docs/api/REST/8.13.2/#api/2/user-getUser)
or
REST [GET /rest/api/2/user/anonymization](https://docs.atlassian.com/software/jira/docs/api/REST/8.13.0/#api/2/user/anonymization-validateUserAnonymization)
.
The reason to take the user-key is (I think) the fact the Anonymization API is capable
of anonymizing deleted users. Deleted users aren't present in DB-table `cwd_user`, but remains
in DB-table `app_user`.

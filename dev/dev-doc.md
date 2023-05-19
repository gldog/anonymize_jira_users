DEV-DOC
=

# TODOs

- Note at test-repetition:
  Usernames named like a user-key "JIRAUSER12345" aren't anonymized to the real user-key.
  Therefore those users can be found by REST /rest/api/2/user !

- Test: User-name mit Leerzeichen
- Test: Umlaute und fremdsprachige Sonderzeichen.
- At validation: Change "action": "skipped" to "validated"
- Doc: If an export (e.g. from DB) contains a user name with space and it is enclosed in
  quotes (single or double), remove the quotes. Keep a quote only if is definitely part of
  the user name.
- Test: username with "hash": dschoess#1
- If reading the anonymized data from audit-log failed, get data from reporter or
  assignee? => No
- make all sub-commands case-insensitive. E.g. is_anonymized_user_data_complete_for_user()
  maybe in g_users replace "users from infile" with names got from GET /user.
- List all used REST-APIs, and...
- ...check if some Jira system-properties could limit the REST-API results.
  jira.search.views.default.max,
  https://confluence.atlassian.com/adminjiraserver076/limiting-the-number-of-issues-returned-from-a-search-view-such-as-an-rss-feed-941596303.html
    - The above system-property can be viewed
      here: http://localhost:2990/jira/secure/admin/ViewSystemInfo.jspa
- Feature: Find partially anonymized users. The audit-log could be limited in size and
  age! See
    - [Anonymizing users > Troubleshooting](https://confluence.atlassian.com/adminjiraserver/anonymizing-users-992677655.html#Anonymizingusers-troubleshooting)
    - [Retrying anonymization](https://confluence.atlassian.com/adminjiraserver/retrying-anonymization-992677663.html)
    - [Auditing in Jira](https://confluence.atlassian.com/adminjiraserver/auditing-in-jira-938847740.html)
- Query deleted users: `deleted-users`

# Dev-Notes

## Create the .pyz

    python3 -m zipapp anonymize_jira_users

## Call with fresh pyz

    python3 -m zipapp anonymize_jira_users  &&  python3 anonymize_jira_users.pyz

# Technical details

## Deleted users have the e-mail-address "?"

See Jira-source-code:

- UserResource.java: DOC_EXAMPLE_DELETED.emailAddress = "?"
- DefaultUserManager.java: return new ImmutableUser(UNKNOWN_DIRECTORY_ID, userNameOrKey,
  userNameOrKey, "?", false)

TODOs
=

# Open

#### Not yet anonymized user with user-name "jirauser12345" won't be anonymzed

Seen in Jira 8.10.

Jira can anonymized users again. Does Jira think a user is already anonymized
if the name is like an anonymized one?

A "real" anonymized username has the app_user.id in its name.


#### Add tests
- Check if/since which Jira version worklogs are anonymized
- Check activities




#### Some Jira-issues
- [ JRASERVER-70748 Anonymize LDAP users](https://jira.atlassian.com/browse/JRASERVER-70748)




#### How to retrieve deleted users?

#### Regarding the anonymization these are the "Transfered items":

- Project Lead
- Component Lead
- Filters subscriptions

But there are also ownership of

- filters
- boards
- ...

# Test

## Test REST-API against Jira-versions

### Find users `GET /rest/api/2/user/search`

There are voices complaining the API would return 1.000 users max at all, regardless of
the `startAt`-parameter.

But in Jira 8.13.1, the API works as expected. Given a `startAt` of 999, it returns
further 617 users.

Jira 8.7.0: TODO Jira 8.13.1: OK

# ?

Jira Cloud

Are user-names case-insensitive in infile, the /user REST-API, and the validation
REST-API?

in bash: rename report-files by extending them by a date-string.

Must the new_owner_key be a user with permissions to the issue in question?

supplement:

-n NEW_OWNER, --new-owner NEW_OWNER Transfer roles of all anonymized users to the user
with this user-name

"You can choose any user with proper permissions, but it’s probably best to transfer them
to a project admin or somebody who has taken over the tasks of the anonymized user."

User which are a the creator (not the reporter) of an issue can be deleted. Jira replaces
the rendered user by the user-name (not the user-key). As long as the user is not
anonymized, you can see the user-name.

TODO Schedule anonymization of a user with language setting DE

---

# Known issues

TODO The errors in JSON-responses were seen in a different language than set for the
admin. Unclear, if this is the language of the user to be / that were anonymized, or the
Jira system-default.

---

# REST API

## Get user

[GET /rest/api/2/user](https://docs.atlassian.com/software/jira/docs/api/REST/8.13.2/#api/2/user-getUser)

> Returns a user.

## Anonymization

There is a REST API and a Java API. In this document only the REST API is considered, as
it is more flexible to use and more easy to understand.

https://docs.atlassian.com/software/jira/docs/api/REST/8.13.0/#api/2/user/anonymization

### Validate user anonymization

`GET /rest/api/2/user/anonymization`

> Validates user anonymization process.

### Schedule user anonymization

`POST /rest/api/2/user/anonymization`

### Get progress

`GET /rest/api/2/user/anonymization/progress`

TODO

jira-project/jira-components/jira-plugins/jira-rest/jira-rest-plugin/src/main/java/com/atlassian/jira/rest/v2/user/anonymization/UserAnonymizationProgressBean.java

There is the HTTP status code 200 left. If that is returned, I have to look into the JSON
responses "status"- attribute. I haven't a mapping of HTTP status-code to progress "
status"-attribute yet, by I have the list of
"status" values read from the Jira source code. These are:

- COMPLETED The anonymization process finished. Some errors or warnings might be present.
- INTERRUPTED There is no connection with the node that was executing the anonymization
  process. Usually, this means that the node crashed and the anonymization task needs to
  be cleaned up from the cluster.
- IN_PROGRESS The anonymization process is still being performed.
- VALIDATION_FAILED The anonymization process hasn't been started because the validation
  has failed for some anonymization handlers.

### Some use cases

#### Admin tries to anonymize themself

URL: http://localhost:2990/jira/rest/api/2/user/anonymization?userKey=admin

Status: 400 Bad Request

Response:

    {
        "errors": {
            "GENERAL": {
                "errorMessages": [
                    "You can't anonymize yourself."
                ],
                "errors": {}
            }
        },
        "warnings": {},
        "expand": "affectedEntities",
        "userKey": "admin",
        "deleted": false,
        "success": false,
        "operations": [],
        "businessLogicValidationFailed": false
    }

POST http://localhost:2990/jira/rest/api/2/user/anonymization

Status: 202 Accepted

Response:

    {
        "errors": {},
        "warnings": {},
        "userKey": "admin",
        "userName": "admin",
        "fullName": "admin",
        "progressUrl": "/rest/api/2/user/anonymization/progress?taskId=10104",
        "currentProgress": 0,
        "submittedTime": "2020-12-10T13:25:06.127+0100",
        "operations": [],
        "status": "IN_PROGRESS",
        "executingNode": "",
        "isRerun": false,
        "rerun": false
    }

GET http://localhost:2990/jira/rest/api/2/user/anonymization/progress

Status: 200

Response:

    {
        "errors": {
            "GENERAL": {
                "errorMessages": [
                    "You can't anonymize yourself."
                ],
                "errors": {}
            }
        },
        "warnings": {},
        "userKey": "admin",
        "userName": "admin",
        "fullName": "admin",
        "progressUrl": "/rest/api/2/user/anonymization/progress?taskId=10104",
        "currentProgress": 100,
        "submittedTime": "2020-12-10T13:25:06.127+0100",
        "startTime": "2020-12-10T13:25:06.128+0100",
        "finishTime": "2020-12-10T13:25:06.131+0100",
        "operations": [],
        "status": "COMPLETED",
        "executingNode": "",
        "isRerun": false,
        "rerun": false
    }

---

# Useful stuff

## Jira feature requests and bugs

- [JSDSERVER-6886 Allow bulk-nonymizing users](https://jira.atlassian.com/browse/JSDSERVER-6886)
- [JSDSERVER-6881 During the anonymization steps, Jira should additional display the future anonymized user name](https://jira.atlassian.com/browse/JSDSERVER-6881)
- [JRASERVER-71251 Improve User Anonymize Feature](https://jira.atlassian.com/browse/JRASERVER-71251)

## Unordered

REST `DELETE http://localhost:2990/jira/rest/api/2/user?username=user`

Status: 400 Bad Request

    {
        "errorMessages": [
            "Cannot delete user 'user1' because 1 issues are currently assigned to this person."
        ],
        "errors": {}
    }




    {
        "errorMessages": [
            "Cannot delete user 'user1' because they have made 4 comments."
        ],
        "errors": {}
    }

User is synchronized from Active Directory:

Status: 400 Bad Request

    {
        "errorMessages": [
            "Cannot delete user, the user directory is read-only."
        ],
        "errors": {}
    }

## SQLs

### Tables of interest

- `cwd_user`
- `app_user`

### Get a list of user-keys of deleted users

Deleted user have an entry in table `app_user`, but not in `cwd_user` anymore.

    select *
    from app_user
    where au.lower_user_name not in 
      (select lower_user_name from cwd_user)

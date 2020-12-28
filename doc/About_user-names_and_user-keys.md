# About user-names and user-keys

In Jira pre-6.0, Jira had only the user-name as an external and internal representation of a
user. This user-name couldn't be changed. In Jira 6.0 Atlassian introduced the distinction 
between the user-name and the user-key. By this, the user-name could be changed; users 
could be renamed, whereas the internal representation keeps unchanged.

From the Atlassian docs [Renamable Users in JIRA 6.0](https://developer.atlassian.com/server/jira/platform/renamable-users-in-jira-6-0/)

>Introducing the user key
Previously the username field was used both as a display value and also stored as the primary key of the user.
In order to allow usernames to be changed, we obviously need a separate identifier field that is unchangeable.
>
>We have introduced a new field called "key" to users that is a case-sensitive String and will never change (also referred to as the "userkey").
In order to correctly support systems with multiple directories, this key is applicable at the application level, not at the user directory level.
>
>Existing users will get allocated a key that is equal to the lowercase of the username.
This means there is no need to migrate existing data: the stored value is the user key and even if the user's username is later edited, this stored key will remain correct.
(This assumes that you are already lower-casing the stored usernames which was required in order to avoid case-sensitivity bugs).

Since then, user-information is given in two DB-tables: The user-name is given in DB-table
`cwd_user` as `cwd_user.user_name` and `cwd_user.lower_user_name`, whereas the user-key is 
given in the new DB-table `app_user` in `app_user.user_key`. The relation between them is 
`cwd_user.lower_user_name = app_user.lower_user_name`.

The Anonymization REST API takes the user-key. This is in contrast to the admin-UI, which 
takes the user-name. Giving the user-name is convenient, as the user-key is not obvious and 
have to be queried, e. g. by 
REST [GET /rest/api/2/user](https://docs.atlassian.com/software/jira/docs/api/REST/8.13.2/#api/2/user-getUser)
or REST [GET /rest/api/2/user/anonymization](https://docs.atlassian.com/software/jira/docs/api/REST/8.13.0/#api/2/user/anonymization-validateUserAnonymization).
The reason to take the user-key is (I think) the fact the Anonymization API is capable
of anonymizing deleted users. Deleted users aren't present in DB-table `cwd_user`, but remains
in DB-table `app_user`.

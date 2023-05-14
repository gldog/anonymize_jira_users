Testing the Anonymizer
=

# General

Tests are divided into unit- and integration-tests.


# Integration tests

The tests need a running
[Jira test application](https://bitbucket.org/jheger/jira-anonymizinghelper/src/master/).

At starting, Jira performs an upgrade task. It is important to start the integration tests
**after the upgrade task** has been finished.

This is how this looks like in the atlassian-jira.log:

    [INFO] [talledLocalContainer] 2021-03-11 20:35:47,612+0100 localhost-startStop-1 INFO      [c.a.jira.startup.JiraStartupLogger] 
    [INFO] [talledLocalContainer]     
    [INFO] [talledLocalContainer]     ****************
    [INFO] [talledLocalContainer]     Jira starting...
    [INFO] [talledLocalContainer]     ****************
    [INFO] [talledLocalContainer]     
    [INFO] [talledLocalContainer] 2021-03-11 20:35:47,692+0100 localhost-startStop-1 INFO      [c.a.jira.startup.JiraStartupLogger]
    ...
    [INFO] [talledLocalContainer] 2021-03-11 20:37:34,662+0100 Caesium-1-3 INFO ServiceRunner     [c.a.jira.upgrade.LicenseCheckingUpgradeService] 
    [INFO] [talledLocalContainer]     
    [INFO] [talledLocalContainer]     *******************************************************************
    [INFO] [talledLocalContainer]      Upgrade Succeeded! JIRA has been upgraded to build number 812001
    [INFO] [talledLocalContainer]     *******************************************************************
    [INFO] [talledLocalContainer]     
    [INFO] [talledLocalContainer] 2021-03-11 20:37:34,663+0100 Caesium-1-3 INFO ServiceRunner     [c.a.jira.upgrade.UpgradeIndexManager] There are no reindex requests of type [IMMEDIATE, DELAYED] so none will be run

Now you can start testing.

#!/usr/local/bin/python3

from base_test_class import BaseTestClass


class RunHelper(BaseTestClass):

    def test_create_user_u1(self):
        r = self.jira_application.admin_session.user_create(
            'new_owner', 'new_owner@example.com', 'The New Owner', password='1')

        user_name = 'u1'
        r = self.jira_application.admin_session.user_create(
            user_name, 'u1@example.com', 'U 1', password='1')
        r = self.jira_application.user_activate(user_name, False)

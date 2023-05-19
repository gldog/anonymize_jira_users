#!/usr/local/bin/python3

from base_test_class import BaseTestClass


class RunHelper(BaseTestClass):
    """For arbitrary manual tests. """

    def test_create_user_u1(self):
        print("test_create_user_u1()")
        r = self.jira_application.admin_session.user_create(
            'new_owner', 'new_owner@example.com', 'The New Owner', password='1')

        user_name = 'u1'
        r = self.jira_application.admin_session.user_create(
            user_name, 'u1@example.com', 'U 1', password='1')
        r = self.jira_application.user_activate(user_name, False)

    def test_create_users(self):
        print("test_create_users()")
        r = self.jira_application.admin_session.user_create(
            'new_owner', 'new_owner@example.com', 'The New Owner', password='1')

        print("test_create_users() B")

        for i in range(1, 4):
            user_name = f'u{i}'
            print(f"test_create_users() {user_name}")
            r = self.jira_application.admin_session.user_create(
                user_name, f'{user_name}@example.com', f'U {i}', password='1')
            r = self.jira_application.user_activate(user_name, False)

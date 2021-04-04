import dataclasses
import json
from dataclasses import dataclass, asdict, field
from typing import List


@dataclass
class AnonymizedUser:
    user_name: str = None
    user_key: str = None
    user_display_name: str = None
    active: bool = False
    deleted: bool = False
    filter_error_message: str = ''
    anonymized_user_name: str = None
    anonymized_user_key: str = None
    anonymized_user_display_name: str = None
    action: str = 'anonymized'


@dataclass()
class ExpectedTestResultGenerator:
    predicted_anonymized_userdata: dict = None
    overview: dict = None
    users: List[AnonymizedUser] = field(default_factory=list)
    report: dict = None

    def set_predicted_anonymized_userdata(self, data):
        self.predicted_anonymized_userdata = data

    def set_overview(self, overview):
        self.overview = overview

    def add_user(self, anonymized_user):
        """Make a copy of the AnonymizedUser and add it to the list. """
        self.users.append(AnonymizedUser(**dataclasses.asdict(anonymized_user)))
        pass

    def generate(self):
        self.report = {'overview': self.overview, 'users': self.users}
        for user in self.users:
            paud_for_user = self.predicted_anonymized_userdata[user.user_name]
            if user.anonymized_user_name is None:
                user.anonymized_user_name = 'jirauser{}'.format(paud_for_user['appUserId'])
            if user.anonymized_user_key is None:
                user.anonymized_user_key = 'JIRAUSER{}'.format(paud_for_user['appUserId'])
            if user.anonymized_user_display_name is None:
                user.anonymized_user_display_name = paud_for_user['anonymizedDisplayName']


predicted_anonymized_userdata = {
    "user2name": {
        "appUserId": 10202,
        "anonymizedDisplayName": "user-c4ccb"
    },
    "user1name": {
        "appUserId": 10201,
        "anonymizedDisplayName": "user-03404"
    }
}

if __name__ == '__main__':
    expected_test_results_generator = ExpectedTestResultGenerator()
    expected_test_results_generator.set_predicted_anonymized_userdata(predicted_anonymized_userdata)
    expected_test_results_generator.set_overview({
        "number_of_users_in_user_list_file": 11,
        "number_of_skipped_users": 2,
        "number_of_anonymized_users": 9,
        "is_background_reindex_triggered": False
    })

    anonymized_user = AnonymizedUser(user_name='user1name', user_key='user1key', user_display_name='user1displayname',
                                     active=False, deleted=False, action='anonymized',
                                     filter_error_message='')

    expected_test_results_generator.add_user(anonymized_user)
    anonymized_user.user_name = 'user2name'
    anonymized_user.anonymized_user_key = None
    expected_test_results_generator.add_user(anonymized_user)
    expected_test_results_generator.generate()

    # print(f"user1 repr: {anonymized_user}")
    # print(f"user1 asdict: {asdict(anonymized_user)}")
    print(f"generator repr: {expected_test_results_generator}")
    print(f"asdict(expected_test_results_generator): {asdict(expected_test_results_generator)}")
    print(f"generator.report asdict: {json.dumps(asdict(expected_test_results_generator)['report'], indent=2)}")

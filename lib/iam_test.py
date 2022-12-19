from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
from datetime import datetime
import json
import base64
import csv


aws = AWSAPI()


def signal_when_test_starts_and_finishes(test):
    '''decorator that signals in the report that test was run'''
    def wrap(*args, **kwargs):
        with open(args[0], "a") as rf:
            rf.write(f"\nStarting test {test.__name__}\n")
        result = test(*args, **kwargs)
        with open(args[0], "a") as rf:
            rf.write(f"Ending test {test.__name__}\n")
        return result
    return wrap


def find_age_of_credentials(checked_position):
    searched_date = datetime.strptime(
        checked_position[:10] + " " + checked_position[11:19], "%Y-%m-%d %H:%M:%S")
    current_date = datetime.now()
    age = current_date - searched_date
    return age.days


def generate_and_save_credntial_report(report_file, aws_api, credential_report="credential_report.csv"):
    try:
        aws.execute(
            ["iam", "generate-credential-report"])
        output = aws_api.execute(["iam", "get-credential-report"])
    except AWSCLIError as e:
        with open(report_file, 'a') as rf:
            rf.write(
                f"An error ocured while generating new credential report: {e}\n")
    else:
        encoded_report = json.loads(output)["Content"]
        with open("credential_report.csv", "w") as cr:
            cr.write(base64.b64decode(encoded_report).decode("utf-8"))


@signal_when_test_starts_and_finishes
def no_root_access_key_exist(report_file, aws_api):
    try:
        output = aws_api.execute(["iam", "get-account-summary"])
    except AWSCLIError as e:
        with open(report_file, 'a') as rf:
            rf.write(
                f"An error ocured while running test no_root_access_key_exist: {e}\n")
    else:
        number_of_root_access_keys = json.loads(
            output)["SummaryMap"]["AccountAccessKeysPresent"]
        if number_of_root_access_keys == 0:
            with open(report_file, 'a') as rf:
                rf.write("No rooot access keys exist: True\n")
        else:
            with open(report_file, 'a') as rf:
                rf.write(
                    f"ALERT: No rooot access keys exist: False, number of access keys:{number_of_root_access_keys}\n")


@signal_when_test_starts_and_finishes
def multifactor_auth_for_root(report_file, aws_api):
    try:
        output = aws_api.execute(["iam", "get-account-summary"])
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test multifactor_auth_for_root: {e}\n")
    else:
        number_of_root_access_keys = json.loads(
            output)["SummaryMap"]["AccountMFAEnabled"]
        if number_of_root_access_keys == 1:
            with open(report_file, 'a') as rf:
                rf.write("mulfifactor authentication for root enabled: True\n")
        else:
            with open(report_file, 'a') as rf:
                rf.write(
                    "ALERT: mulfifactor authentication for root enabled: False\n")


@signal_when_test_starts_and_finishes
def when_root_was_last_used(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[0] == "<root_account>":
                days_since_root_password_was_last_used = find_age_of_credentials(
                    user[4])
                if days_since_root_password_was_last_used < 7:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: root acccount was accessed in the last 7 days: Password was last used: {user[4]}\n")
                else:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"Root acccount was not accessed in the last 7 days: Password was last used: {user[4]}, Access key 1 was last used: {user[10]}, Access key 2 was last used: {user[15]}\n")


@signal_when_test_starts_and_finishes
def password_longer_than_14_chars(report_file, aws_api):
    try:
        output = aws_api.execute(["iam", "get-account-password-policy"])
    except AWSCLIError as e:
        with open(report_file, 'a') as rf:
            rf.write(
                f"An error ocured while running test password_longer_than_14_chars: {e}\n")
    else:
        minimal_password_length = json.loads(
            output)["PasswordPolicy"]["MinimumPasswordLength"]
        if minimal_password_length < 14:
            with open(report_file, "a") as rf:
                rf.write(
                    f"ALERT: minimal password length: {minimal_password_length}, shoud be: 14\n")
        else:
            with open(report_file, "a") as rf:
                rf.write(f"Minimal password length is long enough\n")


@signal_when_test_starts_and_finishes
def password_reuse_prevention(report_file, aws_api):
    try:
        output = aws_api.execute(["iam", "get-account-password-policy"])
        password_reuse_prevention = json.loads(
            output)["PasswordPolicy"]["PasswordReusePrevention"]
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test password_reuse_prevention: {e}\n")
    except KeyError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test password_reuse_prevention: {e} is not enabled\n")
    else:
        if password_reuse_prevention < 24:
            with open(report_file, "a") as rf:
                rf.write(
                    f"ALERT: password_reuse_prevention is set to: {password_reuse_prevention}, shoud be: 24\n")
        else:
            with open(report_file, "a") as rf:
                rf.write(f"password_reuse_prevention is set correctly as 24\n")


@signal_when_test_starts_and_finishes
def mfa_enabled_for_all_users(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                if user[7] == "false":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT! User {user[0]} does not have mfa enabled\n")
                else:
                    with open(report_file, 'a') as rf:
                        rf.write(f"User {user[0]} has mfa enabled\n")


@signal_when_test_starts_and_finishes
def check_for_unused_keys(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                if user[8] == "true" and user[10] == "N/A":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: User {user[0]} has an unused access_key_1\n")
                if user[13] == "true" and user[15] == "N/A":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: User {user[0]} has an unused access_key_2\n")


@signal_when_test_starts_and_finishes
def check_for_unused_credentials_older_than_45_days(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                if user[4] != "no_information":
                    days_since_password_was_last_used = find_age_of_credentials(
                        user[4])
                    if days_since_password_was_last_used > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use password in the last 45 days- you should disable this method of autentiction \n")
                else:
                    password_age = find_age_of_credentials(user[5])
                    if password_age > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use their current password and it's older than 45 days\n")

            if user[8] == "true":
                if user[10] != "N/A":
                    days_since_key_1_was_last_used = find_age_of_credentials(
                        user[10])
                    if days_since_key_1_was_last_used > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use access_key_1 in the last 45 days- you should disable this method of autentiction \n")
                else:
                    key_1_age = find_age_of_credentials(user[9])
                    if key_1_age > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use access_key_1 and access_key_1 is older than 45 days- you should rotate this key\n")
            if user[13] == "true":
                if user[15] != "N/A":
                    days_since_key_2_was_last_used = find_age_of_credentials(
                        user[15])
                    if days_since_key_2_was_last_used > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use access_key_2 in the last 45 days- you should disable this method of autentiction \n")
                else:
                    key_2_age = find_age_of_credentials(user[14])
                    if key_2_age > 45:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: User {user[0]} did not use access_key_2 and access_key_2 is older than 45 days- you should rotate this key\n")


@signal_when_test_starts_and_finishes
def users_have_multiple_access_keys(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[8] == "true" and user[13] == "true":
                with open(report_file, 'a') as rf:
                    rf.write(
                        f"User {user[0]} has two access keys active- you should disable at least on of them")


@signal_when_test_starts_and_finishes
def define_age_of_access_key(report_file, credential_report="credential_report.csv"):
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[8] == "true":
                key_1_age = find_age_of_credentials(user[9])
                if key_1_age > 90:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: access_key_1 if user {user[0]} is older than 90 days\n")
            if user[13] == "true":
                key_2_age = find_age_of_credentials(user[14])
                if key_2_age > 90:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: access_key_2 if user {user[0]} is older than 90 days\n")


@signal_when_test_starts_and_finishes
def users_recieve_permissions_only_through_groups(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["iam", "list-users", "--query", "Users[*].UserName", "--output", "text"])
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test users_recieve_permissions_only_through_groups: {e}\n")
    else:
        users = output.strip("\n").split("\t")
        for user in users:
            try:
                attached_user_policies = json.loads(aws_api.execute(
                    ["iam", "list-attached-user-policies", "--user-name", user]))
                user_policies = json.loads(aws_api.execute(
                    ["iam", "list-user-policies", "--user-name", user]))
            except AWSCLIError as e:
                with open(report_file, "a") as rf:
                    rf.write(
                        f"An error ocured while running test users_recieve_permissions_only_through_groups: {e}\n")
            else:
                if len(attached_user_policies["AttachedPolicies"]) > 0:
                    with open(report_file, "a") as rf:
                        rf.write(
                            f"ALERT: User {user} has following attached policies: {attached_user_policies['AttachedPolicies']}; it's recommended to give permissions only through groups!\n")
                if len(user_policies["PolicyNames"]) > 0:
                    with open(report_file, "a") as rf:
                        rf.write(
                            f"ALERT: User {user} has following user policies: {user_policies['PolicyNames']}; it's recommended to give permissions only through groups!\n")


@signal_when_test_starts_and_finishes
def full_administrative_privileges_are_not_attached(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["iam", "list-policies", "--only-attached", "--output", "json"])
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test full_administrative_privileges_are_not_attached: {e}\n")
    else:
        policies = json.loads(output)["Policies"]
        for policy in policies:
            try:
                policy_version_properties = aws_api.execute(
                    ["iam", "get-policy-version", "--policy-arn", policy["Arn"], "--version-id", policy["DefaultVersionId"], "--output", "json"])
            except:
                with open(report_file, "a") as rf:
                    rf.write(
                        f"An error ocured while running test full_administrative_privileges_are_not_attached: {e}\n")
            else:
                policy_properties = json.loads(policy_version_properties)[
                    "PolicyVersion"]
                statement = policy_properties["Document"]["Statement"]
                for position in statement:
                    if position["Effect"] == "Allow" and position["Action"] == "*" and position["Resource"] == "*":
                        with open(report_file, "a") as rf:
                            rf.write(
                                f"ALERT: allowed * action in policy to * resources; policy Arn: {policy['Arn']}; version: {policy['DefaultVersionId']}; Make sure that only neccessary actions are allowed\n")


@signal_when_test_starts_and_finishes
def support_role_has_been_created(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["iam", "list-policies", "--query", "Policies[?PolicyName == 'AWSSupportAccess']", "--output", "json"])
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test support_role_has_been_created: {e}\n")
    else:
        aws_support_access = json.loads(output)
        arn = aws_support_access[0]["Arn"]
        try:
            entities_for_policy = aws_api.execute(
                ["iam", "list-entities-for-policy", "--policy-arn", arn, "--output", "json"])
        except AWSCLIError as e:
            with open(report_file, "a") as rf:
                rf.write(
                    f"An error ocured while running test support_role_has_been_created: {e}\n")
        else:
            policy_roles = json.loads(entities_for_policy)["PolicyRoles"]
            if len(policy_roles) == 0:
                with open(report_file, "a") as rf:
                    rf.write(
                        f"ALERT: There is no support role for managing incidents with AWS Support\n")


@signal_when_test_starts_and_finishes
def expired_certificates_stored_in_aws_iam(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["iam", "list-server-certificates", "--output", "json"])
    except AWSCLIError as e:
        with open(report_file, "a") as rf:
            rf.write(
                f"An error ocured while running test expired_certificates_stored_in_aws_iam: {e}\n")
    else:
        server_cerificates_metadata_list = json.loads(
            output)["ServerCertificateMetadataList"]
        for certificate in server_cerificates_metadata_list:
            expiration = certificate["Expiration"]
            expiration_date = datetime.strptime(
                expiration[:10] + " " + expiration[11:19], "%Y-%m-%d %H:%M:%S")
            current_date = datetime.now()
            if current_date > expiration_date:
                with open(report_file, "a") as rf:
                    rf.write(
                        f"ALERT: Certificate with id: {certificate['ServerCertificateId']} is expired. You should delete it\n")


@signal_when_test_starts_and_finishes
def iam_access_analyzer_is_enabled_for_all_regions(report_file, aws_api, regions):
    for region in regions:
        try:
            output = aws_api.execute(
                ["accessanalyzer", "list-analyzers", "--region", region, "--output", "json"])
        except AWSCLIError as e:
            with open(report_file, "a") as rf:
                rf.write(
                    f"An error ocured while running test iam_access_analyzer_is_enabled_for_all_regions: {e}\n")
        else:
            analyzers = json.loads(output)["analyzers"]
            for analyzer in analyzers:
                if analyzer["status"] == "ACTIVE":
                    break
            else:
                with open(report_file, "a") as rf:
                    rf.write(
                        f"ALERT: in {region} region there aren't any working access analyzers\n")

"""
generate_and_save_credntial_report("report", aws)
no_root_access_key_exist("report", aws)
multifactor_auth_for_root("report", aws)
when_root_was_last_used("report")
password_longer_than_14_chars("report", aws)
password_reuse_prevention("report", aws)
mfa_enabled_for_all_users("report")
check_for_unused_keys("report")
check_for_unused_credentials_older_than_45_days("report")
users_have_multiple_access_keys("report")
define_age_of_access_key("report")
users_recieve_permissions_only_through_groups("report", aws)
full_administrative_privileges_are_not_attached("report", aws)
support_role_has_been_created("report", aws)
expired_certificates_stored_in_aws_iam("report", aws)
iam_access_analyzer_is_enabled_for_all_regions("report", aws, ["us-east-1", "eu-central-1"])
"""
from awscliv2.api import AWSAPI
from datetime import datetime
import json
import base64
import csv
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import find_age_of_credentials
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws

aws = AWSAPI()


def generate_and_save_credntial_report(report_file, credential_report="credential_report.csv"):
    make_request_to_aws(report_file, [
                        "iam", "generate-credential-report"], "generate_and_save_credntial_report")
    output = make_request_to_aws(report_file, [
        "iam", "get-credential-report"], "generate_and_save_credntial_report")
    encoded_report = json.loads(output)["Content"]
    with open(credential_report, "w") as cr:
        cr.write(base64.b64decode(encoded_report).decode("utf-8"))


@signal_when_test_starts_and_finishes
def no_root_access_key_exist(report_file):
    write_message_in_report(
        report_file,  "Control 1.4")
    output = make_request_to_aws(report_file, [
                                 "iam", "get-account-summary"], "no_root_access_key_exist")
    number_of_root_access_keys = json.loads(
        output)["SummaryMap"]["AccountAccessKeysPresent"]
    if number_of_root_access_keys == 0:
        write_message_in_report(
            report_file, "No root access keys exist: True")
    else:
        write_message_in_report(
            report_file, f"ALERT: At leas one root access keys exists; number of access keys:{number_of_root_access_keys}")


@signal_when_test_starts_and_finishes
def mfs_is_enabled_for_the_root_user(report_file):
    write_message_in_report(
        report_file,  "Control 1.5")
    output = make_request_to_aws(report_file, [
                                 "iam", "get-account-summary"], "mfs_is_enabled_for_the_root_user")
    number_of_root_access_keys = json.loads(
        output)["SummaryMap"]["AccountMFAEnabled"]
    if number_of_root_access_keys == 1:
        write_message_in_report(
            report_file, "mulfifactor authentication for root enabled: True")
    else:
        write_message_in_report(
            report_file, "ALERT: mulfifactor authentication for root enabled: False")


@signal_when_test_starts_and_finishes
def eliminate_use_of_the_root_user_for_administrative_and_daily_task(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.7")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[0] == "<root_account>":
                days_since_root_password_was_last_used = find_age_of_credentials(
                    user[4])
                if days_since_root_password_was_last_used < 7:
                    write_message_in_report(
                        report_file, f"ALERT: root acccount was accessed in the last 7 days: Password was last used: {user[4]}")
                else:
                    write_message_in_report(
                        report_file, f"Root acccount was not accessed in the last 7 days: Password was last used: {user[4]}, Access key 1 was last used: {user[10]}, Access key 2 was last used: {user[15]}")


@signal_when_test_starts_and_finishes
def iam_password_policy_requires_minimum_length_of_14(report_file):
    write_message_in_report(
        report_file,  "Control 1.8")
    output = make_request_to_aws(report_file, [
                                 "iam", "get-account-password-policy"], "iam_password_policy_requires_minimum_length_of_14")
    minimal_password_length = json.loads(
        output)["PasswordPolicy"]["MinimumPasswordLength"]
    if minimal_password_length < 14:
        write_message_in_report(
            report_file, f"ALERT: minimal password length: {minimal_password_length}, shoud be: 14")
    else:
        write_message_in_report(
            report_file, f"Minimal password length is long enough")


@signal_when_test_starts_and_finishes
def iam_password_policy_prevents_password_reuse(report_file):
    write_message_in_report(
        report_file,  "Control 1.9")
    output = make_request_to_aws(report_file, [
                                 "iam", "get-account-password-policy"], "iam_password_policy_prevents_password_reuse")
    try:
        password_reuse_prevention = json.loads(
            output)["PasswordPolicy"]["PasswordReusePrevention"]
    except KeyError as e:
        write_message_in_report(
            report_file, f"An error ocured while running test iam_password_policy_prevents_password_reuse: {e} is not enabled")
    else:
        if password_reuse_prevention < 24:
            write_message_in_report(
                report_file, f"ALERT: password_reuse_prevention is set to: {password_reuse_prevention}, shoud be: 24")
        else:
            write_message_in_report(
                report_file, "password_reuse_prevention is set correctly as 24")


@signal_when_test_starts_and_finishes
def mfa_enabled_for_all_users(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.10")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                if user[7] == "false":
                    write_message_in_report(
                        report_file, f"ALERT! User {user[0]} does not have mfa enabled")
                else:
                    write_message_in_report(
                        report_file, f"User {user[0]} has mfa enabled")


@signal_when_test_starts_and_finishes
def check_for_unused_keys(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.11")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                if user[8] == "true" and user[10] == "N/A":
                    write_message_in_report(
                        report_file, f"ALERT: User {user[0]} has an unused access_key_1")
                else:
                    write_message_in_report(
                        report_file, f"Setting Access_key_1 for User {user[0]} is set correctly")
                if user[13] == "true" and user[15] == "N/A":
                    write_message_in_report(
                        report_file, f"ALERT: User {user[0]} has an unused access_key_2")
                else:
                    write_message_in_report(
                        report_file, f"Setting Access_key_2 for User {user[0]} is set correctly")


def check_credential_usage(report_file, name, last_used, last_rotated, credential):
    """
    auxilary method for check_for_unused_credentials_older_than_45_days
    """
    if last_used != "N/A" and last_used != "no_information":
        days_since_credential_was_last_used = find_age_of_credentials(
            last_used)
        if days_since_credential_was_last_used > 45:
            write_message_in_report(
                report_file, f"ALERT: User {name} did not use current {credential} in the last 45 days- you should disable this method of autentiction")
        else:
            write_message_in_report(
                report_file, f"{credential} for user {name} is set correctly")
    else:
        credential_age = find_age_of_credentials(last_rotated)
        if credential_age > 45:
            write_message_in_report(
                report_file, f"ALERT: User {name} did not use current {credential} and thier {credential} is older than 45 days- you should update {credential}")
        else:
            write_message_in_report(
                report_file, f"{credential} for user {name} is set correctly")


@signal_when_test_starts_and_finishes
def check_for_unused_credentials_older_than_45_days(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.12")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[3] == "true":
                check_credential_usage(
                    report_file, user[0], user[4], user[5], "password")

            if user[8] == "true":
                check_credential_usage(
                    report_file, user[0], user[10], user[9], "key_access_1")

            if user[13] == "true":
                check_credential_usage(
                    report_file, user[0], user[15], user[14], "key_access_2")


@signal_when_test_starts_and_finishes
def users_have_multiple_access_keys(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.13")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[8] == "true" and user[13] == "true":
                write_message_in_report(
                    report_file, f"ALERT: User {user[0]} has two access keys active- you should disable one of them")
            else:
                write_message_in_report(
                    report_file, f"User {user[0]} has no more than 1 key active")


@signal_when_test_starts_and_finishes
def access_keys_are_rotated_every_90_dys_or_less(report_file, credential_report="credential_report.csv"):
    write_message_in_report(
        report_file,  "Control 1.14")
    with open(credential_report, "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for user in csv_reader:
            if user[8] == "true":
                key_1_age = find_age_of_credentials(user[9])
                if key_1_age > 90:
                    write_message_in_report(
                        report_file, f"ALERT: access_key_1 if user {user[0]} is older than 90 days")
                else:
                    write_message_in_report(
                        report_file, f"access_key_1 is fresh enough")
            if user[13] == "true":
                key_2_age = find_age_of_credentials(user[14])
                if key_2_age > 90:
                    write_message_in_report(
                        report_file, f"ALERT: access_key_2 if user {user[0]} is older than 90 days")
                else:
                    write_message_in_report(
                        report_file, f"access_key_2 is fresh enough")


@signal_when_test_starts_and_finishes
def users_recieve_permissions_only_through_groups(report_file):
    write_message_in_report(
        report_file,  "Control 1.15")
    output = make_request_to_aws(report_file, [
                                 "iam", "list-users", "--query", "Users[*].UserName", "--output", "text"], "users_recieve_permissions_only_through_groups")
    users = output.strip("\n").split("\t")
    for user in users:
        attached_user_policies_result = make_request_to_aws(report_file, [
                                                            "iam", "list-attached-user-policies", "--user-name", user], "users_recieve_permissions_only_through_groups")
        attached_user_policies = json.loads(attached_user_policies_result)
        user_policies_result = make_request_to_aws(report_file, [
            "iam", "list-user-policies", "--user-name", user], "users_recieve_permissions_only_through_groups")
        user_policies = json.loads(user_policies_result)
        if len(attached_user_policies["AttachedPolicies"]) > 0:
            write_message_in_report(
                report_file, f"ALERT: User {user} has following attached policies: {attached_user_policies['AttachedPolicies']}; it's recommended to give permissions only through groups!")
        else:
            write_message_in_report(
                report_file, f"User {user} does not have attached polices")
        if len(user_policies["PolicyNames"]) > 0:
            write_message_in_report(
                report_file, f"ALERT: User {user} has following user policies: {user_policies['PolicyNames']}; it's recommended to give permissions only through groups!")
        else:
            write_message_in_report(
                report_file, f"User {user} does not have user polices")


@signal_when_test_starts_and_finishes
def full_administrative_privileges_are_not_attached(report_file):
    write_message_in_report(
        report_file,  "Control 1.16")
    output = make_request_to_aws(report_file, [
        "iam", "list-policies", "--only-attached", "--output", "json"], "full_administrative_privileges_are_not_attached")
    policies = json.loads(output)["Policies"]
    for policy in policies:
        policy_version_properties = make_request_to_aws(report_file, [
                                                        "iam", "get-policy-version", "--policy-arn", policy["Arn"], "--version-id", policy["DefaultVersionId"], "--output", "json"], "full_administrative_privileges_are_not_attached")
        policy_properties = json.loads(policy_version_properties)[
            "PolicyVersion"]
        statement = policy_properties["Document"]["Statement"]
        for position in statement:
            if position["Effect"] == "Allow" and position["Action"] == "*" and position["Resource"] == "*":
                write_message_in_report(
                    report_file, f"ALERT: allowed * action in policy to * resources; policy Arn: {policy['Arn']}; version: {policy['DefaultVersionId']}; Make sure that only neccessary actions are allowed")
            else:
                write_message_in_report(
                    report_file, f"Test passed for policy Arn: {policy['Arn']}; version: {policy['DefaultVersionId']};")


@signal_when_test_starts_and_finishes
def support_role_has_been_created(report_file):
    write_message_in_report(
        report_file,  "Control 1.17")
    output = make_request_to_aws(report_file, [
                                 "iam", "list-policies", "--query", "Policies[?PolicyName == 'AWSSupportAccess']", "--output", "json"], "support_role_has_been_created")
    aws_support_access = json.loads(output)
    arn = aws_support_access[0]["Arn"]
    entities_for_policy = make_request_to_aws(report_file, [
                                              "iam", "list-entities-for-policy", "--policy-arn", arn, "--output", "json"], "support_role_has_been_created")
    policy_roles = json.loads(entities_for_policy)["PolicyRoles"]
    if len(policy_roles) == 0:
        write_message_in_report(
            report_file, f"ALERT: There is no support role for managing incidents with AWS Support")
    else:
        write_message_in_report(
            report_file, f"Support role for managing incidents with AWS Support exists")


@signal_when_test_starts_and_finishes
def expired_certificates_stored_in_aws_iam_are_removed(report_file):
    write_message_in_report(
        report_file,  "Control 1.19")
    output = make_request_to_aws(report_file, [
                                 "iam", "list-server-certificates", "--output", "json"], "expired_certificates_stored_in_aws_iam_are_removed")
    server_cerificates_metadata_list = json.loads(
        output)["ServerCertificateMetadataList"]
    if len(server_cerificates_metadata_list) == 0:
        write_message_in_report(
            report_file, f"Currently there are 0 certificates stored")
    for certificate in server_cerificates_metadata_list:
        expiration = certificate["Expiration"]
        expiration_date = datetime.strptime(
            expiration[:10] + " " + expiration[11:19], "%Y-%m-%d %H:%M:%S")
        current_date = datetime.now()
        if current_date > expiration_date:
            write_message_in_report(
                report_file, f"ALERT: Certificate with id: {certificate['ServerCertificateId']} is expired. You should delete it")
        else:
            write_message_in_report(
                report_file, f"Certificate with id: {certificate['ServerCertificateId']} is valid")


@signal_when_test_starts_and_finishes
def iam_access_analyzer_is_enabled_for_all_regions(report_file, regions):
    write_message_in_report(
        report_file,  "Control 1.20")
    for region in regions:
        output = make_request_to_aws(report_file, [
                                     "accessanalyzer", "list-analyzers", "--region", region, "--output", "json"], "iam_access_analyzer_is_enabled_for_all_regions")
        analyzers = json.loads(output)["analyzers"]
        for analyzer in analyzers:
            if analyzer["status"] == "ACTIVE":
                write_message_in_report(
                    report_file, f"In {region} region there is at least one working access analuzer")
                break
        else:
            write_message_in_report(
                report_file, f"ALERT: in {region} region there aren't any working access analyzers")


"""
generate_and_save_credntial_report("iam_report")
no_root_access_key_exist("iam_report")
mfs_is_enabled_for_the_root_user("iam_report")
eliminate_use_of_the_root_user_for_administrative_and_daily_task("iam_report")
iam_password_policy_requires_minimum_length_of_14("iam_report")
iam_password_policy_prevents_password_reuse("iam_report")
mfa_enabled_for_all_users("iam_report")
check_for_unused_keys("iam_report")
check_for_unused_credentials_older_than_45_days("iam_report")
users_have_multiple_access_keys("iam_report")
access_keys_are_rotated_every_90_dys_or_less("iam_report")
users_recieve_permissions_only_through_groups("iam_report")
full_administrative_privileges_are_not_attached("iam_report")
support_role_has_been_created("iam_report")
expired_certificates_stored_in_aws_iam_are_removed("iam_report")
iam_access_analyzer_is_enabled_for_all_regions(
    "iam_report", ["us-east-1", "eu-central-1"])
"""

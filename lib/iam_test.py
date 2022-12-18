from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
from datetime import datetime
import time
import json
import base64
import csv


aws = AWSAPI()


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


def when_root_was_last_used(report_file, aws_api):
    with open("credential_report.csv", "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for row in csv_reader:
            if row[0] == "<root_account>":
                password_last_used_date = datetime.strptime(
                    row[4][:10] + " " + row[4][11:19], "%Y-%m-%d %H:%M:%S")
                current_date = datetime.now()
                difference = current_date - password_last_used_date
                if difference.days < 7:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: root acccount was accessed in the last 7 days: Password was last used: {row[4]}\n")
                else:
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"Root acccount was not accessed in the last 7 days: Password was last used: {row[4]}, Access key 1 was last used: {row[10]}, Access key 2 was last used: {row[15]}\n")


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


def password_reuse_preventrion(report_file, aws_api):
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


def mfa_enabled_for_all_users(report_file, aws_api):
    with open("credential_report.csv", "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for row in csv_reader:
            if row[3] == "true":
                if row[7] == "false":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT! User {row[0]} does not have mfa enabled\n")
                else:
                    with open(report_file, 'a') as rf:
                        rf.write(f"User {row[0]} has mfa enabled\n")


def check_for_unused_keys(report_file, aws_api):
    with open("credential_report.csv", "r") as cr:
        csv_reader = csv.reader(cr, delimiter=",")
        for row in csv_reader:
            if row[3] == "true":
                if row[8] == "true" and row[10] == "N/A":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: User {row[0]} has an unused access_key_1\n")
                if row[13] == "true" and row[15] == "N/A":
                    with open(report_file, 'a') as rf:
                        rf.write(
                            f"ALERT: User {row[0]} has an unused access_key_2\n")


#def unused_credentials_does_not_exist(report_file, aws_api):

    # generate_and_save_credntial_report("report", aws)
    # no_root_access_key_exist("report", aws)
    # multifactor_auth_for_root("report", aws)
    # when_root_was_last_used("report", aws)
    # password_longer_than_14_chars("report", aws)
    # password_reuse_preventrion("report", aws)
    # mfa_enabled_for_all_users("report", aws)
    # check_for_unused_keys

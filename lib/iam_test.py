from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
from datetime import datetime
import time
import json
import base64
import csv


aws = AWSAPI()


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
        with open(report_file, 'a') as rf:
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
                rf.write("mulfifactor authentication for root enabled: False\n")


def when_root_was_last_used(report_file, aws_api):
    try:
        aws_api.execute(["iam", "generate-credential-report"])
        output = aws_api.execute(["iam", "get-credential-report"])

    except AWSCLIError as e:
        print(f"An error ocured:\n{e}")

    else:
        encoded_report = json.loads(output)["Content"]
        with open("credential_report.csv", "w") as cr:
            cr.write(base64.b64decode(encoded_report).decode("utf-8"))
        with open("credential_report.csv", "r") as cr:
            csv_reader = csv.reader(cr, delimiter=",")
            for row in csv_reader:
                if row[0] == "<root_account>":
                    password_last_used_date = datetime.strptime(
                        row[4][:10] + " " + row[4][11:19], "%Y-%m-%d %H:%M:%S")
                    current_date = datetime.now()
                    difference = current_date - password_last_used_date
                    if difference.days < 14:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"ALERT: root acccount was accessed in the last 7 days: Password was last used: {row[4]}\n")
                    else:
                        with open(report_file, 'a') as rf:
                            rf.write(
                                f"Root acccount was not accessed in the last 7 days: Password was last used: {row[4]}, Access key 1 was last used: {row[10]}, Access key 2 was last used: {row[15]}\n")


# no_root_access_key_exist("report", aws)
# multifactor_auth_for_root("report", aws)
when_root_was_last_used("report", aws)

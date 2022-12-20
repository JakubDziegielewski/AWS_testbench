from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
import json
from json import JSONDecodeError
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import find_age_of_credentials
from auxilary_module import write_message_in_report

aws = AWSAPI()


def get_list_of_s3_buckets(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["s3api", "list-buckets", "--output", "json"])
    except AWSCLIError as e:
        write_message_in_report(
            report_file, f"An error ocured while getting list of s3 buckets: {e}")
    else:
        return (json.loads(output)["Buckets"])


def get_specific_bucket_configuration(report_file, aws_api, config, name, keyword):
    try:
        configuration = aws_api.execute(
            ["s3api", config, "--bucket", name, "--output", "json"])
        result = json.loads(configuration)[keyword]
    except AWSCLIError as e:
        write_message_in_report(
            report_file, f"An error ocured while running test s3_buckets_employ_encryption_at_rest: {e}")
    except JSONDecodeError as e:
        write_message_in_report(
            report_file, f"ALERT: bucket {name} does not return correct config, checked configuration ({config}) probably does not exist: {e}")
    else:
        return result


@signal_when_test_starts_and_finishes
def s3_buckets_employ_encryption_at_rest(report_file, aws_api):

    buckets = get_list_of_s3_buckets(report_file, aws_api)

    for bucket in buckets:
        name = bucket["Name"]
        configuration = get_specific_bucket_configuration(
            report_file, aws_api, "get-bucket-encryption", name, "ServerSideEncryptionConfiguration")
        if configuration != None:
            rules = configuration["Rules"]
            for rule in rules:
                if "ApplyServerSideEncryptionByDefault" in rule:
                    algorithm = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                    if algorithm == "AES256" or algorithm == "aws:kms":
                        write_message_in_report(
                            report_file, f"Recommended encryption algorithm  ({algorithm}) is used in bucket {name}")
                    else:
                        write_message_in_report(
                            report_file, f"ALERT: Unrecommended encryption algorithm  ({algorithm}) is used in bucket {name}")
                else:
                    write_message_in_report(
                        report_file, f"ALERT: Server side encryption is not applied by default")


@signal_when_test_starts_and_finishes
def s3_bucket_policy_is_set_to_deny_http_requests(report_file, aws_api):
    buckets = get_list_of_s3_buckets(report_file, aws_api)
    for bucket in buckets:
        name = bucket["Name"]
        policy = get_specific_bucket_configuration(
            report_file, aws_api, "get-bucket-policy", name, "Policy")
        if policy != None:
            statement = json.loads(policy)["Statement"]
            for statement_property in statement:
                if statement_property["Effect"] == "Deny" and statement_property["Condition"]["Bool"]["aws:SecureTransport"] == "false":
                    write_message_in_report(
                        report_file, f"Bucket {name} denies http requests {name}")
                    break
            else:
                write_message_in_report(
                    report_file, f"ALERT: Bucket {name} does not deny http requests {name}")


@signal_when_test_starts_and_finishes
def mfa_delete_is_enabled(report_file, aws_api):
    buckets = get_list_of_s3_buckets(report_file, aws_api)
    for bucket in buckets:
        name = bucket["Name"]
        bucket_versioning = aws_api.execute(
            ["s3api", "get-bucket-versioning", "--bucket", name, "--output", "json"])
        if bucket_versioning:  # bucket_versioning will be an empty string if versioning is not enabled
            properties = json.loads(bucket_versioning)
            if "MfaDelete" in properties and properties["MfaDelete"] == "Enabled":
                write_message_in_report(
                    report_file, f"MFA Delete is enabled in {name} bucket"
                )

            else:
                write_message_in_report(
                    report_file, f"ALERT: MFA Delete is not enabled in {name} bucket"
                )
        else:
            write_message_in_report(
                report_file, f"ALERT: Versioning is not enabled in {name} bucket"
            )


"""
s3_buckets_employ_encryption_at_rest("s3_report", aws)
s3_bucket_policy_is_set_to_deny_http_requests("s3_report", aws)
mfa_delete_is_enabled("s3_report", aws)
"""

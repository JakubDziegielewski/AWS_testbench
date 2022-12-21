import json
from json import JSONDecodeError
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws


def get_list_of_s3_buckets(report_file):
    output = make_request_to_aws(report_file, [
        "s3api", "list-buckets", "--output", "json"], "get_list_of_s3_buckets")
    return (json.loads(output)["Buckets"])


def get_specific_bucket_configuration(report_file, config, name, keyword):
    configuration = make_request_to_aws(report_file, [
        "s3api", config, "--bucket", name, "--output", "json"], "get_specific_bucket_configuration")
    try:
        result = json.loads(configuration)[keyword]
    except JSONDecodeError as e:
        write_message_in_report(
            report_file, f"ALERT: bucket {name} does not return correct config, checked configuration ({config}) probably does not exist: {e}")
    else:
        return result


@signal_when_test_starts_and_finishes
def s3_buckets_employ_encryption_at_rest(report_file):
    write_message_in_report(
        report_file,  "Control 2.1.1")
    buckets = get_list_of_s3_buckets(report_file)
    for bucket in buckets:
        name = bucket["Name"]
        configuration = get_specific_bucket_configuration(
            report_file, "get-bucket-encryption", name, "ServerSideEncryptionConfiguration")
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
def s3_bucket_policy_is_set_to_deny_http_requests(report_file):
    write_message_in_report(
        report_file,  "Control 2.1.2")
    buckets = get_list_of_s3_buckets(report_file)
    for bucket in buckets:
        name = bucket["Name"]
        policy = get_specific_bucket_configuration(
            report_file, "get-bucket-policy", name, "Policy")
        if policy != None:
            statement_list = json.loads(policy)["Statement"]
            for statement in statement_list:
                if statement["Effect"] == "Deny" and "Condition" in statement and statement["Condition"]["Bool"]["aws:SecureTransport"] == "false":
                    write_message_in_report(
                        report_file, f"Bucket {name} denies http requests {name}")
                    break
            else:
                write_message_in_report(
                    report_file, f"ALERT: Bucket {name} does not deny http requests {name}")


@signal_when_test_starts_and_finishes
def mfa_delete_is_enabled(report_file):
    write_message_in_report(
        report_file,  "Control 2.1.3")
    buckets = get_list_of_s3_buckets(report_file)
    for bucket in buckets:
        name = bucket["Name"]
        bucket_versioning = make_request_to_aws(report_file, [
                                                "s3api", "get-bucket-versioning", "--bucket", name, "--output", "json"], "mfa_delete_is_enabled")
        if bucket_versioning:  # bucket_versioning will be an empty string if versioning is not enabled
            try:
                properties = json.loads(bucket_versioning)
            except JSONDecodeError as e:
                write_message_in_report(
                    report_file, f"ALERT: bucket {name} does not return correct configuration; message: {bucket_versioning}; Error: {e}")
            else:
                if "MfaDelete" in properties and properties["MfaDelete"] == "Enabled":
                    write_message_in_report(
                        report_file, f"MFA Delete is enabled in {name} bucket")
                else:
                    write_message_in_report(
                        report_file, f"ALERT: MFA Delete is not enabled in {name} bucket")
        else:
            write_message_in_report(
                report_file, f"ALERT: Versioning is not enabled in {name} bucket")


@signal_when_test_starts_and_finishes
def s3_buckets_are_configured_with_block_public_access_bucket_setting(report_file):
    write_message_in_report(
        report_file,  "Control 2.1.5")
    buckets = get_list_of_s3_buckets(report_file)
    for bucket in buckets:
        name = bucket["Name"]
        public_access_block_configuration = get_specific_bucket_configuration(
            report_file, "get-public-access-block", name, "PublicAccessBlockConfiguration")
        if public_access_block_configuration != None:
            for setting in public_access_block_configuration:
                if not public_access_block_configuration[setting]:
                    write_message_in_report(
                        report_file, f"ALERT: Public access to s3 bucket {name} allowed; {setting} is set to 'false'"
                    )
                else:
                    write_message_in_report(
                        report_file, f"{setting} in s3 bucket {name} is set correctly"
                    )


"""
s3_buckets_employ_encryption_at_rest("s3_report")
s3_bucket_policy_is_set_to_deny_http_requests("s3_report")
mfa_delete_is_enabled("s3_report")
s3_buckets_are_configured_with_block_public_access_bucket_setting(
    "s3_report")
"""

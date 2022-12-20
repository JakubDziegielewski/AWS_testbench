from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
import json
from json import JSONDecodeError
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import find_age_of_credentials
from auxilary_module import write_message_in_report

aws = AWSAPI()


@signal_when_test_starts_and_finishes
def s3_buckets_employ_encryption_at_rest(report_file, aws_api):
    try:
        output = aws_api.execute(
            ["s3api", "list-buckets", "--output", "json"])
    except AWSCLIError as e:
        write_message_in_report(
            report_file, f"An error ocured while running test s3_buckets_employ_encryption_at_rest: {e}")
    else:
        buckets = json.loads(output)["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]
            try:
                encryption_configuration = aws_api.execute([
                    "s3api", "get-bucket-encryption", "--bucket", name, "--output", "json"])
                rules = json.loads(encryption_configuration)[
                    "ServerSideEncryptionConfiguration"]["Rules"]
            except AWSCLIError as e:
                write_message_in_report(
                    report_file, f"An error ocured while running test s3_buckets_employ_encryption_at_rest: {e}")
            except JSONDecodeError as e:
                write_message_in_report(
                    report_file, f"ALERT: bucket {name} does not employ encryption"
                )
            else:
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

s3_buckets_employ_encryption_at_rest("s3_report", aws)

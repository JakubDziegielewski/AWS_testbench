from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report

aws = AWSAPI()


def get_all_db_instances(report_file, aws_api, region):
    try:
        output = aws_api.execute(
            ["rds", "describe-db-instances", "--output", "json", "--region", region])
    except AWSCLIError as e:
        write_message_in_report(
            report_file, f"An error ocured while trying to describe db instances: {e}")
    else:
        db_instances = json.loads(output)["DBInstances"]
        return db_instances


def check_one_setting_in_all_rds_instances(report_file, aws_api, regions, setting):
    for region in regions:
        db_instances = get_all_db_instances(report_file, aws_api, region)
        for db_instance in db_instances:
            if not db_instance[setting]:
                write_message_in_report(
                    report_file, f"ALERT: {setting} is not enabled in the database with id: {db_instance['DBInstanceIdentifier']}")
            else:
                write_message_in_report(
                    report_file, f"{setting} is set correctly as enabled in the database with id: {db_instance['DBInstanceIdentifier']}")


@signal_when_test_starts_and_finishes
def encryption_is_enabled_for_rds_instances(report_file, aws_api, regions):
    write_message_in_report(
        report_file,  "Control 2.3.1")
    check_one_setting_in_all_rds_instances(
        report_file, aws_api, regions, "StorageEncrypted")


@signal_when_test_starts_and_finishes
def auto_minor_version_upgrade_feature_is_enabled_for_rds_instances(report_file, aws_api, regions):
    write_message_in_report(
        report_file,  "Control 2.3.2")
    check_one_setting_in_all_rds_instances(
        report_file, aws_api, regions, "AutoMinorVersionUpgrade")


@signal_when_test_starts_and_finishes
def public_access_is_not_given_to_rds_instance(report_file, aws_api, regions):
    write_message_in_report(report_file, "Control 2.3.3")
    for region in regions:
        db_instances = get_all_db_instances(report_file, aws_api, region)
        for db_instance in db_instances:
            if db_instance["PubliclyAccessible"]:
                write_message_in_report(
                    report_file, f"ALERT: Setting 'PubliclyAccessible' is enabled in the database with id: {db_instance['DBInstanceIdentifier']}")
            else:
                write_message_in_report(
                    report_file, f"Setting 'PubliclyAccessible' is set correctly in the database with id: {db_instance['DBInstanceIdentifier']}")


"""
encryption_is_enabled_for_rds_instances(
    "rds_report", aws, ["us-east-1", "eu-central-1"])
auto_minor_version_upgrade_feature_is_enabled_for_rds_instances(
    "rds_report", aws, ["us-east-1", "eu-central-1"])
public_access_is_not_given_to_rds_instance("rds_report", aws, ["us-east-1", "eu-central-1"])
"""

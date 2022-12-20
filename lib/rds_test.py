from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report

aws = AWSAPI()


def get_all_db_instances(report_file, aws_api, region):
    try:
        output = aws_api.execute(["rds", "describe-db-instances", "--output", "json", "--region", region])
    except AWSCLIError as e:
         write_message_in_report(
                report_file, f"An error ocured while trying to describe db instances: {e}")
    else:
        db_instances= json.loads(output)["DBInstances"]
        return db_instances

@signal_when_test_starts_and_finishes
def encryption_is_enabled_for_rds_instances(report_file, aws_api, regions):
    for region in regions:
        db_instances= get_all_db_instances(report_file, aws_api, region)
        for db_instance in db_instances:
            if not db_instance["StorageEncrypted"]:
                write_message_in_report(
                report_file, f"ALERT: Encryption is not enabled in the database with id: {db_instance['DBInstanceIdentifier']}")


encryption_is_enabled_for_rds_instances("rds_report", aws, ["us-east-1", "eu-central-1"])

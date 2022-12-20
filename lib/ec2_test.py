from awscliv2.api import AWSAPI
from awscliv2.exceptions import AWSCLIError
import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report

aws = AWSAPI()

@signal_when_test_starts_and_finishes
def ebs_volume_encryption_is_enabled_in_all_regions(report_file, aws_api, regions):
    for region in regions:
        try:
            output = aws_api.execute(
                ["ec2", "get-ebs-encryption-by-default", "--region", region])
        except AWSCLIError as e:
            write_message_in_report(
                report_file, f"An error ocured while running test ebs_volume_encryption_is_enabled_in_all_regions: {e}")
        else:
            ebs_encryption_by_default = json.loads(output)["EbsEncryptionByDefault"]
            if not ebs_encryption_by_default:
                write_message_in_report(
                report_file, f"ALERT: in {region} ebs is not encrypted by default")

ebs_volume_encryption_is_enabled_in_all_regions("ec2_report", aws, ["us-east-1", "eu-central-1"])

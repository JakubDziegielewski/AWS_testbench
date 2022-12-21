import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws


@signal_when_test_starts_and_finishes
def ebs_volume_encryption_is_enabled_in_all_regions(report_file, regions):
    write_message_in_report(
        report_file,  "Control 2.2.1")
    for region in regions:
        output = make_request_to_aws(report_file, [
                                     "ec2", "get-ebs-encryption-by-default", "--region", region], "ebs_volume_encryption_is_enabled_in_all_regions")
        ebs_encryption_by_default = json.loads(
            output)["EbsEncryptionByDefault"]
        if not ebs_encryption_by_default:
            write_message_in_report(
                report_file, f"ALERT: in {region} ebs is not encrypted by default")
        else:
            write_message_in_report(
                report_file, f"EBS is encrypted by default in {region} region")


"""
ebs_volume_encryption_is_enabled_in_all_regions("ec2_report", ["us-east-1", "eu-central-1"])
"""

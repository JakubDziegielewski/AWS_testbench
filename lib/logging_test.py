from awscliv2.api import AWSAPI
import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report

aws = AWSAPI()

"""
@signal_when_test_starts_and_finishes
def cloudtrail_is_enabled_in_all_regions(report_file, aws_api):
    write_message_in_report(report_file, "Control 3.1")
    try:
"""
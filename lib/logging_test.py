import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws


def check_if_cloudtrail_is_logging(report_file, name):
    output = make_request_to_aws(report_file, [
                                 "cloudtrail", "get-trail-status", "--name", name], "check_if_cloudtrail_is_logging")
    trail_status = json.loads(output)
    return trail_status["IsLogging"]


def get_event_selectors(report_file, name):
    output = make_request_to_aws(report_file, [
                                 "cloudtrail", "get-event-selectors", "--trail-name", name])


@signal_when_test_starts_and_finishes
def cloudtrail_is_enabled_in_all_regions(report_file):
    write_message_in_report(report_file, "Control 3.1")
    output = make_request_to_aws(report_file, [
                                 "cloudtrail", "describe-trails"], "cloudtrail_is_enabled_in_all_regions")
    trail_list = json.loads(output)["trailList"]
    for trail in trail_list:
        if trail["IsMultiRegionTrail"]:
            name = trail["Name"]
            if check_if_cloudtrail_is_logging(report_file, name):
                event_selectors_text = make_request_to_aws(report_file, [
                                                           "cloudtrail", "get-event-selectors", "--trail-name", name], "cloudtrail_is_enabled_in_all_regions")
                event_selectors = json.loads(event_selectors_text)
                if "AdvancedEventSelectors" in event_selectors:
                    for event_selector in event_selectors["AdvancedEventSelectors"]:
                        if "FieldSelectors" in event_selector:
                            field_selectors = event_selector["FieldSelectors"]
                            management_event_are_logged = False
                            read_write_privileges = True
                            for field_selector in field_selectors:
                                if field_selector["Field"] == "readOnly":
                                    read_write_privileges = False
                                elif field_selector["Field"] == "eventCategory":
                                    event_categories = field_selector["Equals"]
                                    if "Management" in event_categories:
                                        management_event_are_logged = True
                        if management_event_are_logged and read_write_privileges:
                            write_message_in_report(report_file, f"")
                            break


cloudtrail_is_enabled_in_all_regions("logging_report")

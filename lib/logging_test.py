import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws


def describe_trials(report_file):
    output = make_request_to_aws(
        report_file, ["cloudtrail", "describe-trails"], "describe_trials")
    return json.loads(output)["trailList"]


def check_if_cloudtrail_is_logging(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-trail-status", "--name", name], "check_if_cloudtrail_is_logging")
    trail_status = json.loads(output)
    return trail_status["IsLogging"]


def get_event_selectors(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-event-selectors", "--trail-name", name], "get_event_selectors")
    return json.loads(output)


def check_if_management_in_advanced_event_selectors(advanced_event_selectors):
    for event_selector in advanced_event_selectors:
        if "FieldSelectors" in event_selector:
            for selector in event_selector["FieldSelectors"]:
                if selector["Field"] == "eventCategory" and "Management" in selector["Equals"]:
                    return True
    return False


def check_if_read_only_in_advanced_selectors(advanced_event_selectors):
    for event_selector in advanced_event_selectors:
        if "FieldSelectors" in event_selector:
            for selector in event_selector["FieldSelectors"]:
                if selector["Field"] == "readOnly":
                    return True
    return False


def check_if_read_write_and_include_management_events_in_event_selectors(event_selectors):
    for event_selector in event_selectors:
        if "ReadWriteType" in event_selector and "IncludeManagementEvents" in event_selector:
            if event_selector["ReadWriteType"] == "All" and event_selector["IncludeManagementEvents"]:
                return True
    return False


@ signal_when_test_starts_and_finishes
def cloudtrail_is_enabled_in_all_regions(report_file):
    write_message_in_report(report_file, "Control 3.1")
    trail_list = describe_trials(report_file)
    for trail in trail_list:
        if trail["IsMultiRegionTrail"]:
            name = trail["Name"]
            if check_if_cloudtrail_is_logging(report_file, name):
                event_selectors = get_event_selectors(report_file, name)
                if "AdvancedEventSelectors" in event_selectors:
                    if check_if_management_in_advanced_event_selectors(event_selectors["AdvancedEventSelectors"]):
                        if not check_if_read_only_in_advanced_selectors(event_selectors["AdvancedEventSelectors"]):
                            write_message_in_report(
                                report_file, f"There exist at least one cloudtrail logging management events in all regions: {name}")
                            break
                elif "EventSelectors" in event_selectors:
                    if check_if_read_write_and_include_management_events_in_event_selectors(event_selectors["EventSelectors"]):
                        write_message_in_report(
                            report_file, f"There exist at least one cloudtrail logging management events in all regions: {name}")
                        break
    else:
        write_message_in_report(
                            report_file, f"ALERT: there are not any cloudtrails logging management events in all regions")


"""
cloudtrail_is_enabled_in_all_regions("logging_report")
"""
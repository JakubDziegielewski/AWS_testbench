import json
from json import JSONDecodeError
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws
from datetime import datetime

date = datetime.now().strftime("%Y_%m_%d")


def describe_trials(report_file):
    output = make_request_to_aws(
        report_file, ["cloudtrail", "describe-trails"])
    with open(f"trails_{date}", "w") as trails:
        trails.write(json.dumps(json.loads(output), indent=4))


def get_trails_from_file(trails_file):
    with open(trails_file, "r") as trails:
        return json.load(trails)["trailList"]


def get_event_selectors(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-event-selectors", "--trail-name", name])
    return json.loads(output)


def get_multi_region_trails():
    trails = get_trails_from_file(f"trails_{date}")
    multi_region_trials = list()
    for trail in trails:
        if trail["IsMultiRegionTrail"]:
            multi_region_trials.append(trail)
    return multi_region_trials


def get_trail_status(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-trail-status", "--name", name])
    return json.loads(output)


def check_if_read_only_in_event_selector(event_selector):
    for selector in event_selector["FieldSelectors"]:
        if selector["Field"] == "readOnly":
            return True
    return False


def check_if_management_and_read_write_in_advanced_event_selectors(advanced_event_selectors):
    for event_selector in advanced_event_selectors:
        if "FieldSelectors" in event_selector:
            if check_if_read_only_in_event_selector(event_selector):
                continue
            for selector in event_selector["FieldSelectors"]:
                if selector["Field"] == "eventCategory" and "Management" in selector["Equals"]:
                    return True
    return False


def check_if_read_write_and_include_management_events_in_event_selectors(event_selectors):
    for event_selector in event_selectors:
        if "ReadWriteType" in event_selector and "IncludeManagementEvents" in event_selector:
            if event_selector["ReadWriteType"] == "All" and event_selector["IncludeManagementEvents"]:
                return True
    return False


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_unauthorized_API_calls(report_file):
    write_message_in_report(report_file, "Control 4.1")
    multi_region_trails = get_multi_region_trails()
    for trail in multi_region_trails:
        name = trail["Name"]
        cloud_watch_logs_log_gropu_arn = trail["CloudWatchLogsLogGroupArn"]
        trail_status = get_trail_status(report_file, trail)
        if trail_status["IsLogging"]:
            event_selectors = get_event_selectors(report_file, name)
            if "AdvancedEventSelectors" in event_selectors:
                if check_if_management_and_read_write_in_advanced_event_selectors(event_selectors["AdvancedEventSelectors"]):
                    write_message_in_report(
                        report_file, f"There exist at least one cloudtrail logging management events in all regions: {name}")
            elif "EventSelectors" in event_selectors:
                if check_if_read_write_and_include_management_events_in_event_selectors(event_selectors["EventSelectors"]):
                    write_message_in_report(
                        report_file, f"There exist at least one cloudtrail logging management events in all regions: {name}")
        else:
            write_message_in_report(
                report_file, f"ALERT: CLoudtrail {name} is not active")


# describe_trials("monitoring_report")
log_metric_filter_and_alarm_exist_for_unauthorized_API_calls(
    "monitoring_report")
# if check_if_trail_is_active("monitoring_report", "management-events"):
#    print(1)

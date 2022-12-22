import json
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws
from auxilary_module import find_age_of_setting


def describe_trials(report_file):
    output = make_request_to_aws(
        report_file, ["cloudtrail", "describe-trails"])
    return json.loads(output)["trailList"]


def get_trail_status(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-trail-status", "--name", name])
    return json.loads(output)


def get_event_selectors(report_file, name):
    output = make_request_to_aws(report_file, [
        "cloudtrail", "get-event-selectors", "--trail-name", name])
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


def get_bucket_acl_grants(report_file, name):
    output = make_request_to_aws(report_file, [
                                 "s3api", "get-bucket-acl", "--bucket", name])
    return json.loads(output)["Grants"]


def check_for_group_access_in_acl(grants, uri):
    for grant in grants:
        grantee = grant["Grantee"]
        if grantee["Type"] == "Group" and "URI" in grantee and grantee["URI"] == uri:
            return True
    return False


def get_bucket_policy(report_file, name):
    output = make_request_to_aws(
        report_file, ["s3api", "get-bucket-policy", "--bucket", name])
    return json.loads(output)["Policy"]


def check_if_policy_allows_all_actions(policy):
    statement = json.loads(policy)["Statement"]
    for rule in statement:
        if rule["Effect"] == "Allow" and rule["Principal"] == "*":
            return True
    return False


@signal_when_test_starts_and_finishes
def cloudtrail_is_enabled_in_all_regions(report_file):
    write_message_in_report(report_file, "Control 3.1")
    trail_list = describe_trials(report_file)
    for trail in trail_list:
        if trail["IsMultiRegionTrail"]:
            name = trail["Name"]
            if get_trail_status(report_file, name)["IsLogging"]:
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


@signal_when_test_starts_and_finishes
def cloudtrail_log_file_validation_is_enabled(report_file):
    write_message_in_report(report_file, "Control 3.2")
    trail_list = describe_trials(report_file)
    for trail in trail_list:
        if trail["LogFileValidationEnabled"]:
            write_message_in_report(
                report_file, f"Cloudtrail {trail['Name']} has log file validation enabled")
        else:
            write_message_in_report(
                report_file, f"ALERT: Cloudtrail {trail['Name']} does not have log file validation enabled")


@signal_when_test_starts_and_finishes
def s3_bucket_used_to_store_cloudtrail_logs_is_not_publicly_accessible(report_file):
    write_message_in_report(report_file, "Control 3.3")
    trail_list = describe_trials(report_file)
    for trail in trail_list:
        name = trail["S3BucketName"]
        grants = get_bucket_acl_grants(report_file, name)
        if check_for_group_access_in_acl(grants, "http://acs.amazonaws.com/groups/global/AllUsers"):
            write_message_in_report(
                report_file, f"ALERT: public access is allowed for s3 bucket {name}, which is used for storing logs from cloudtrail")
        else:
            write_message_in_report(
                report_file, f"s3 bucket {name} is secured from public access")
        if check_for_group_access_in_acl(grants, "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):
            write_message_in_report(
                report_file, f"ALERT: Access for anyone with AWS accountis allowed for s3 bucket {name}, which is used for storing logs from cloudtrail")
        else:
            write_message_in_report(
                report_file, f"s3 bucket {name} is secured from authenticated users")
        policy = get_bucket_policy(report_file, name)
        if check_if_policy_allows_all_actions(policy):
            write_message_in_report(
                report_file, f"ALERT: Policy for s3 bucket {name} has a rule that allows full control")
        else:
            write_message_in_report(
                report_file, f"Policy for s3 bucket {name} is configured properly")


@signal_when_test_starts_and_finishes
def trails_are_integrated_with_cloudwatch_logs(report_file):
    write_message_in_report(report_file, "Control 3.4")
    trail_list = describe_trials(report_file)
    for trial in trail_list:
        name = trial["Name"]
        if "CloudWatchLogsLogGroupArn" in trial:
            trail_status = get_trail_status(report_file, name)
            if "LatestCloudWatchLogsDeliveryTime" in trail_status and find_age_of_setting(trail_status["LatestCloudWatchLogsDeliveryTime"]) < 1:
                write_message_in_report(
                    report_file, f"CloudTrail {name} is integrated with CloudWatch and works properly")
            else:
                write_message_in_report(
                    report_file, f"ALERT: CloudTrail {name} is integrated with CloudWatch but does not work properly")
        else:
            write_message_in_report(
                report_file, f"ALERT: CloudTrail {name} is not integrated with CloudWatch")


@signal_when_test_starts_and_finishes
def aws_config_is_enabled_in_all_regions(report_file):
    write_message_in_report(report_file, "Control 3.5")
    configuration_recorders_text = make_request_to_aws(
        report_file, ["configservice", "describe-configuration-recorders"])
    configuration_recorders = json.loads(configuration_recorders_text)[
        "ConfigurationRecorders"]
    for configuration_recorder in configuration_recorders:
        if configuration_recorder["recordingGroup"]["allSupported"] and configuration_recorder["recordingGroup"]["includeGlobalResourceTypes"]:
            write_message_in_report(
                report_file, "There exist a configurtion recorder that supports all resource types")
            configuration_recorder_status_text = make_request_to_aws(
                report_file, ["configservice", "describe-configuration-recorder-status"])
            configuration_recorder_status = json.loads(configuration_recorder_status_text)[
                "ConfigurationRecordersStatus"]
            for status in configuration_recorder_status:
                if status["recording"] and status["lastStatus"] == "SUCCESS":
                    write_message_in_report(
                        report_file, "Configuration recorder works properly")
                    break
            else:
                write_message_in_report(
                    report_file, "ALERT: default configuration recorder does not work properly")
            break
    else:
        write_message_in_report(
            report_file, "ALERT: AWS Config does not have a recorder that supports all resource types")


@signal_when_test_starts_and_finishes
def s3_bucket_access_logging_is_enabled_on_the_cloudtrail_s3_bucket(report_file):
    write_message_in_report(report_file, "Control 3.6")
    buckets_for_clodtrails_text = make_request_to_aws(
        report_file, ["cloudtrail", "describe-trails", "--query", "trailList[*].S3BucketName"])
    buckets_for_clodtrails = json.loads(buckets_for_clodtrails_text)
    for bucket in buckets_for_clodtrails:
        logging_enabled = make_request_to_aws(
            report_file, ["s3api", "get-bucket-logging", "--bucket", bucket])
        if logging_enabled:
            write_message_in_report(
                report_file, f"Bucket {bucket} has logging enabled")
        else:
            write_message_in_report(
                report_file, f"ALERT: bucket {bucket} does not have logging enabled")


@signal_when_test_starts_and_finishes
def cloudtrail_logs_are_encrypted_at_rest_using_kms_cmk(report_file):
    write_message_in_report(report_file, "Control 3.7")
    trails = describe_trials(report_file)
    for trail in trails:
        if "KmsKeyId" in trail:
            write_message_in_report(
                report_file, f"cloudtrial {trail['Name']} logs are encrypted at rest using KMS CMKs")
        else:
            write_message_in_report(
                report_file, f"ALERT: cloudtrial {trail['Name']} logs are not encrypted at rest using KMS CMKs")



@signal_when_test_starts_and_finishes
def rotation_for_customer_created_summetric_cmks_is_enabled(report_file):
    write_message_in_report(report_file, "Control 3.8")
    key_list_text = make_request_to_aws(report_file, ["kms", "list-keys"])
    key_list = json.loads(key_list_text)["Keys"]
    for key in key_list:
        key_id = key["KeyId"]
        key_details_text = make_request_to_aws(report_file, ["kms", "describe-key", "--key-id", key_id])
        key_details = json.loads(key_details_text)["KeyMetadata"]
        if "KeySpec" in key_details and key_details["KeySpec"] == "SYMMETRIC_DEFAULT":
            rotation_status_text = make_request_to_aws(report_file, ["kms", "get-key-rotation-status", "--key-id", key_id])
            rotation_status = json.loads(rotation_status_text)
            if "KeyRotationEnabled" in rotation_status and rotation_status["KeyRotationEnabled"]:
                write_message_in_report(report_file, f"Key with id {key_id} has rotation enabled")
            else:
                write_message_in_report(report_file, f"ALERT: Key with id {key_id} does not have rotation enabled")


"""
cloudtrail_is_enabled_in_all_regions("logging_report")
cloudtrail_log_file_validation_is_enabled("logging_report")
s3_bucket_used_to_store_cloudtrail_logs_is_not_publicly_accessible(
    "logging_report")
trails_are_integrated_with_cloudwatch_logs("logging_report")
aws_config_is_enabled_in_all_regions("logging_report")
s3_bucket_access_logging_is_enabled_on_the_cloudtrail_s3_bucket("logging_report")
cloudtrail_logs_are_encrypted_at_rest_using_kms_cmk("logging_report")
rotation_for_customer_created_summetric_cmks_is_enabled("logging_report")"""

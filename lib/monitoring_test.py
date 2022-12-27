import json
from json import JSONDecodeError
from auxilary_module import signal_when_test_starts_and_finishes
from auxilary_module import write_message_in_report
from auxilary_module import make_request_to_aws
from datetime import datetime

date = datetime.now().strftime("%Y_%m_%d")

patterns = {
    "unauthorized_api_calls": '{ ($.errorCode = *UnauthorizedOperation) || ($.errorCode = AccessDenied*) || ($.sourceIPAddress!=delivery.logs.amazonaws.com) || ($.eventName!=HeadBucket) }',
    "management_console_sign_in_without_mfa": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
    "usage_of_root_account": '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    "iam_policy_changes": '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}',
    "cloudtrail_configuration_changes": '{ ($.eventName = CreateTrail) || ($.eventName =UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging)|| ($.eventName = StopLogging) }',
    "aws_management_console_authentication_failures": '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }',
    "disabling_or_scheduled_deletion_of_customer_created_cmks": '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }',
    "s3_bucket_policy_changes": '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }',
    "aws_config_configuration_changes": '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }',
    "security_group_changes": '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }',
    "changes_to_network_access_control_lists": '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }',
    "changes_to_network_gateways": '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }',
    "route_table_changes": '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }',
    "vpc_changes": '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }',
    "aws_organizations_changes": '{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }'
}


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


def check_if_trail_captures_all_management_events(report_file, name):
    event_selectors = get_event_selectors(report_file, name)
    if "AdvancedEventSelectors" in event_selectors:
        if check_if_management_and_read_write_in_advanced_event_selectors(event_selectors["AdvancedEventSelectors"]):
            return True
    elif "EventSelectors" in event_selectors:
        if check_if_read_write_and_include_management_events_in_event_selectors(event_selectors["EventSelectors"]):
            return True
    return False


def get_cloudwatch_alarms_for_filter(report_file, metric_name):
    alarms_text = make_request_to_aws(report_file, [
                                      "cloudwatch", "describe-alarms", "--query", f"MetricAlarms[?MetricName == '{metric_name}']"])
    return json.loads(alarms_text)


def check_if_at_least_one_alarm_has_a_subscriber(report_file, alarms):
    for alarm in alarms:
        if check_if_at_least_one_subscriber_to_sns_topic(report_file, alarm["AlarmActions"]):
            return True
    return False


def check_if_at_least_one_active_arn_in_subscribtion(subscriptions):
    for subscription in subscriptions:
        if "SubscriptionArn" in subscription and len(subscription["SubscriptionArn"]) > 0:
            return True
    return False


def check_if_at_least_one_subscriber_to_sns_topic(report_file, alarms_arn):
    for alarm_arn in alarms_arn:
        subscriptions_text = make_request_to_aws(
            report_file, ["sns", "list-subscriptions-by-topic", "--topic-arn", alarm_arn])
        subscriptions = json.loads(subscriptions_text)["Subscriptions"]
        if check_if_at_least_one_active_arn_in_subscribtion(subscriptions):
            return True
    return False


def check_if_at_least_one_working_metric_transformation(report_file, metric_transformations):
    for metric_transformation in metric_transformations:
        metric_name = metric_transformation["metricName"]
        alarms = get_cloudwatch_alarms_for_filter(
            report_file, metric_name)
        if check_if_at_least_one_alarm_has_a_subscriber(report_file, alarms):
            return True
    return False


def log_metric_filter_and_alarm_exist_for_setting(report_file, setting):
    searched_pattern = patterns[setting]
    multi_region_trails = get_multi_region_trails()
    for trail in multi_region_trails:
        name = trail["Name"]
        group_name = trail["CloudWatchLogsLogGroupArn"].split(":")[6]
        trail_status = get_trail_status(report_file, name)
        if trail_status["IsLogging"]:
            if check_if_trail_captures_all_management_events(report_file, name):
                metric_filters_text = make_request_to_aws(
                    report_file, ["logs", "describe-metric-filters", "--log-group-name", group_name])
                metric_filters = json.loads(metric_filters_text)[
                    "metricFilters"]
                for metric_filter in metric_filters:
                    if searched_pattern == metric_filter["filterPattern"]:
                        write_message_in_report(
                            report_file, f"log metric filter for {setting} exists")
                        metric_transformations = metric_filter["metricTransformations"]
                        if check_if_at_least_one_working_metric_transformation(report_file, metric_transformations):
                            write_message_in_report(
                                report_file, f"Alarm for {setting} exists")
                        else:
                            write_message_in_report(
                                report_file, f"ALERT: alarm does not exist for {setting}")
                        break

                else:
                    write_message_in_report(
                        report_file, f"ALERT: log metric filter for {setting} does not exist")
            else:
                write_message_in_report(
                    report_file, f"ALERT: Cloudtrail {name} does not have full privileges over management events")
        else:
            write_message_in_report(
                report_file, f"ALERT: Cloudtrail {name} is not active")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_unauthorized_API_calls(report_file):
    write_message_in_report(report_file, "Control 4.1")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "unauthorized_api_calls")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_management_console_sign_in_without_mfa(report_file):
    write_message_in_report(report_file, "Control 4.2")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "management_console_sign_in_without_mfa")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_usage_of_root_account(report_file):
    write_message_in_report(report_file, "Control 4.3")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "usage_of_root_account")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_iam_policy_changes(report_file):
    write_message_in_report(report_file, "Control 4.4")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "iam_policy_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_cloudtrail_configuration_changes(report_file):
    write_message_in_report(report_file, "Control 4.5")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "cloudtrail_configuration_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_aws_management_console_authentication_failures(report_file):
    write_message_in_report(report_file, "Control 4.6")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "aws_management_console_authentication_failures")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_disabling_or_scheduled_deletion_of_customer_created_cmks(report_file):
    write_message_in_report(report_file, "Control 4.7")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "disabling_or_scheduled_deletion_of_customer_created_cmks")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_s3_bucket_policy_changes(report_file):
    write_message_in_report(report_file, "Control 4.8")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "s3_bucket_policy_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_aws_config_configuration_changes(report_file):
    write_message_in_report(report_file, "Control 4.9")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "aws_config_configuration_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_security_group_changes(report_file):
    write_message_in_report(report_file, "Control 4.10")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "security_group_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_changes_to_network_access_control_lists(report_file):
    write_message_in_report(report_file, "Control 4.11")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "changes_to_network_access_control_lists")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_changes_to_network_gateways(report_file):
    write_message_in_report(report_file, "Control 4.12")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "changes_to_network_gateways")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_route_table_changes(report_file):
    write_message_in_report(report_file, "Control 4.13")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "route_table_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_vpc_changes(report_file):
    write_message_in_report(report_file, "Control 4.14")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "vpc_changes")


@signal_when_test_starts_and_finishes
def log_metric_filter_and_alarm_exist_for_aws_organizations_changes(report_file):
    write_message_in_report(report_file, "Control 4.15")
    log_metric_filter_and_alarm_exist_for_setting(
        report_file, "aws_organizations_changes")


@signal_when_test_starts_and_finishes
def security_hub_enabled(report_file):
    write_message_in_report(report_file, "Control 4.16")
    hub_description_text = make_request_to_aws(
        report_file, ["securityhub", "describe-hub"])
    try:
        hub_description = json.loads(hub_description_text)
    except JSONDecodeError as e:
        write_message_in_report(report_file, "Securityhub is not enabled")
    else:
        if "HubArn" in hub_description and len(hub_description["HubArn"]) > 0:
            write_message_in_report(report_file, "SecurityHub is enabled")


"""
describe_trials("monitoring_report")
log_metric_filter_and_alarm_exist_for_unauthorized_API_calls(
    "monitoring_report")
log_metric_filter_and_alarm_exist_for_management_console_sign_in_without_mfa(
    "monitoring_report")
log_metric_filter_and_alarm_exist_for_iam_policy_changes("monitoring_report")
log_metric_filter_and_alarm_exist_for_route_table_changes("monitoring_report")
security_hub_enabled("monitoring_report")
"""

from lib import ec2_test
from lib import iam_test
from lib import logging_test
from lib import monitoring_test
from lib import networking_test
from lib import rds_test
from lib import s3_test


def main():
    iam_test.generate_and_save_credntial_report("report")
    iam_test.no_root_access_key_exist("report")
    iam_test.mfs_is_enabled_for_the_root_user("report")
    iam_test.eliminate_use_of_the_root_user_for_administrative_and_daily_task(
        "report")
    iam_test.iam_password_policy_requires_minimum_length_of_14("report")
    iam_test.iam_password_policy_prevents_password_reuse("report")
    iam_test.mfa_enabled_for_all_users("report")
    iam_test.check_for_unused_keys("report")
    iam_test.check_for_unused_credentials_older_than_45_days("report")
    iam_test.users_have_multiple_access_keys("report")
    iam_test.access_keys_are_rotated_every_90_dys_or_less("report")
    iam_test.users_recieve_permissions_only_through_groups("report")
    iam_test.full_administrative_privileges_are_not_attached("report")
    iam_test.support_role_has_been_created("report")
    iam_test.expired_certificates_stored_in_aws_iam_are_removed("report")
    iam_test.iam_access_analyzer_is_enabled_for_all_regions(
        "report", ["us-east-1", "eu-central-1"])

    s3_test.s3_buckets_employ_encryption_at_rest("report")
    s3_test.s3_bucket_policy_is_set_to_deny_http_requests("report")
    s3_test.mfa_delete_is_enabled("report")
    s3_test.s3_buckets_are_configured_with_block_public_access_bucket_setting(
        "report")

    ec2_test.ebs_volume_encryption_is_enabled_in_all_regions(
        "report", ["us-east-1", "eu-central-1"])

    rds_test.encryption_is_enabled_for_rds_instances(
        "report", ["us-east-1", "eu-central-1"])
    rds_test.auto_minor_version_upgrade_feature_is_enabled_for_rds_instances(
        "report", ["us-east-1", "eu-central-1"])
    rds_test.public_access_is_not_given_to_rds_instance(
        "report", ["us-east-1", "eu-central-1"])
    
    logging_test.cloudtrail_is_enabled_in_all_regions("report")
    logging_test.cloudtrail_log_file_validation_is_enabled("report")
    logging_test.s3_bucket_used_to_store_cloudtrail_logs_is_not_publicly_accessible(
        "report")
    logging_test.trails_are_integrated_with_cloudwatch_logs("report")
    logging_test.aws_config_is_enabled_in_all_regions("report")
    logging_test.s3_bucket_access_logging_is_enabled_on_the_cloudtrail_s3_bucket(
        "report")
    logging_test.cloudtrail_logs_are_encrypted_at_rest_using_kms_cmk("report")
    logging_test.rotation_for_customer_created_summetric_cmks_is_enabled("report")
    logging_test.vpc_flow_logging_is_enabled_in_all_vpcs(
        "report", ["us-east-1", "eu-central-1"])
    logging_test.object_level_loggging_for_read_and_write_events_is_enabled_for_s3_bucket(
        "report")

    monitoring_test.describe_trials("report")
    monitoring_test.log_metric_filter_and_alarm_exist_for_unauthorized_API_calls(
        "report")
    monitoring_test.log_metric_filter_and_alarm_exist_for_management_console_sign_in_without_mfa(
        "report")
    monitoring_test.log_metric_filter_and_alarm_exist_for_iam_policy_changes("report")
    monitoring_test.log_metric_filter_and_alarm_exist_for_route_table_changes("report")
    monitoring_test.security_hub_enabled("report")

    networking_test.no_network_acls_allow_ingress_from_all_ips_to_remote_server_administration_ports(
        "report")
    networking_test.no_security_groups_allow_ingress_from_all_ips_to_remote_server_administration_ports("report")
    networking_test.default_security_group_of_every_vpc_restricts_all_traffic("report")


if __name__ == "__main__":
    main()

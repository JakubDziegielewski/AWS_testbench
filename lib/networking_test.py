import json
if __name__ == "__main__":
    from auxilary_module import signal_when_test_starts_and_finishes
    from auxilary_module import write_message_in_report
    from auxilary_module import make_request_to_aws
else:
    from lib.auxilary_module import signal_when_test_starts_and_finishes
    from lib.auxilary_module import write_message_in_report
    from lib.auxilary_module import make_request_to_aws

def check_if_management_ports_in_range(entry):
    if "PortRange" not in entry:
        return True
    else:
        lower_limit = entry["PortRange"]["From"]
        upper_limit = entry["PortRange"]["To"]
        return 22 in range(lower_limit, upper_limit+1) or 3389 in range(lower_limit, upper_limit+1)


def check_if_management_ports_in_ip_permissions(ip_permission):
    if "FromPort" not in ip_permission:
        return True
    else:
        lower_limit = ip_permission["FromPort"]
        upper_limit = ip_permission["ToPort"]
        return 22 in range(lower_limit, upper_limit+1) or 3389 in range(lower_limit, upper_limit+1)


def check_if_all_ips_in_ip_ranges(ip_ranges):
    for ip_range in ip_ranges:
        if "CidrIp" in ip_range and ip_range["CidrIp"] == "0.0.0.0/0":
            return True
    return False


def check_if_all_ips_in_ipv6_ranges(ipv6_ranges):
    for ipv6_range in ipv6_ranges:
        if "CidrIpv6" in ipv6_range and ipv6_range["CidrIpv6"] == "::/0":
            return True
    return False


def check_if_network_acl_allows_traffic_from_all_ips_to_remote_server_administration_ports(network_acl, ipv4=True):
    entries = network_acl["Entries"]
    for entry in entries:
        if ipv4 and "CidrBlock" in entry and entry["CidrBlock"] == "0.0.0.0/0" and not entry["Egress"] and entry["RuleAction"] == "allow":
            if check_if_management_ports_in_range(entry):
                return True
        elif not ipv4 and "Ipv6CidrBlock" in entry and entry["Ipv6CidrBlock"] == "::/0" and not entry["Egress"] and entry["RuleAction"] == "allow":
            if check_if_management_ports_in_range(entry):
                return True
    return False


def check_if_security_group_allows_traffic_from_all_ips_to_remote_server_administration_ports(security_group, ipv4=True):
    ip_permissions = security_group["IpPermissions"]
    for ip_permission in ip_permissions:
        if ipv4 and check_if_all_ips_in_ip_ranges(ip_permission["IpRanges"]):
            if check_if_management_ports_in_ip_permissions(ip_permission):
                return True
        elif not ipv4 and check_if_all_ips_in_ipv6_ranges(ip_permission["Ipv6Ranges"]):
            if check_if_management_ports_in_ip_permissions(ip_permission):
                return True
    return False


@signal_when_test_starts_and_finishes
def no_network_acls_allow_ingress_from_all_ips_to_remote_server_administration_ports(report_file, regions=['us-east-1']):
    write_message_in_report(report_file, "Control 5.1")
    for region in regions:
        network_acls_text = make_request_to_aws(
            report_file, ["ec2", "describe-network-acls", "--region", region])
        network_acls = json.loads(network_acls_text)["NetworkAcls"]
        for network_acl in network_acls:
            if check_if_network_acl_allows_traffic_from_all_ips_to_remote_server_administration_ports(network_acl):
                write_message_in_report(
                    report_file, f"ALERT: Network acl with id {network_acl['NetworkAclId']}  in {region} has a rule that allows ingress from 0.0.0.0/0 to remote server administration ports")
            elif check_if_network_acl_allows_traffic_from_all_ips_to_remote_server_administration_ports(network_acl, ipv4=False):
                write_message_in_report(
                    report_file, f"ALERT: Network acl with id {network_acl['NetworkAclId']}  in {region} has a rule that allows ingress from ::/0 remote server administration ports")
            else:
                write_message_in_report(
                    report_file, f"Network acl with id {network_acl['NetworkAclId']} in {region} does not allow ingress from all ips to remote server administration ports")


@signal_when_test_starts_and_finishes
def no_security_groups_allow_ingress_from_all_ips_to_remote_server_administration_ports(report_file, regions=['us-east-1']):
    write_message_in_report(report_file, "Control 5.2 and Control 5.3")
    for region in regions:
        security_groups_text = make_request_to_aws(
            report_file, ["ec2", "describe-security-groups", "--region", region])
        security_groups = json.loads(security_groups_text)["SecurityGroups"]
        for security_group in security_groups:
            if check_if_security_group_allows_traffic_from_all_ips_to_remote_server_administration_ports(security_group):
                write_message_in_report(
                    report_file, f"ALERT: Security group {security_group['GroupName']}  in {region} has a rule that allows ingress from 0.0.0.0/0 to remote server administration ports")
            else:
                write_message_in_report(
                    report_file, f"Security group {security_group['GroupName']} in {region} does not allow ingress from 0.0.0.0/0 to remote server administration ports")
            if check_if_security_group_allows_traffic_from_all_ips_to_remote_server_administration_ports(security_group, ipv4=False):
                write_message_in_report(
                    report_file, f"ALERT: Security group {security_group['GroupName']}  in {region} has a rule that allows ingress from ::/0 to remote server administration ports")
            else:
                write_message_in_report(
                    report_file, f"Security group {security_group['GroupName']} in {region} does not allow ingress from ::/0 to remote server administration ports")


@signal_when_test_starts_and_finishes
def default_security_group_of_every_vpc_restricts_all_traffic(report_file, regions=['us-east-1']):
    write_message_in_report(report_file, "Control 5.4")
    for region in regions:
        security_groups_text = make_request_to_aws(
            report_file, ["ec2", "describe-security-groups", "--region", region])
        security_groups = json.loads(security_groups_text)["SecurityGroups"]
        for security_group in security_groups:
            if security_group["GroupName"] == "default":
                if len(security_group["IpPermissions"]) > 0:
                    write_message_in_report(
                        report_file, f"ALERT: Default security group in {region} has an inbound rule")
                else:
                    write_message_in_report(
                        report_file, f"Default security group in {region} does not have an inbound rule")
                if len(security_group["IpPermissionsEgress"]) > 0:
                    write_message_in_report(
                        report_file, f"ALERT: Default security group in {region} has an outbound rule")
                else:
                    write_message_in_report(
                        report_file, f"Default security group in {region} does not have an outbound rule")


"""
no_network_acls_allow_ingress_from_all_ips_to_remote_server_administration_ports(
    "networking_report")
no_security_groups_allow_ingress_from_all_ips_to_remote_server_administration_ports("networking_report")
default_security_group_of_every_vpc_restricts_all_traffic("networking_report")
"""

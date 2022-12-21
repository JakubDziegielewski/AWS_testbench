from datetime import datetime
from awscliv2.exceptions import AWSCLIError



def signal_when_test_starts_and_finishes(test):
    '''decorator that signals in the report that test was run'''
    def wrap(*args, **kwargs):
        with open(args[0], "a") as rf:
            rf.write(f"\nStarting test {test.__name__}\n")
        result = test(*args, **kwargs)
        with open(args[0], "a") as rf:
            rf.write(f"Ending test {test.__name__}\n")
        return result
    return wrap


def find_age_of_credentials(checked_position):
    searched_date = datetime.strptime(
        checked_position[:10] + " " + checked_position[11:19], "%Y-%m-%d %H:%M:%S")
    current_date = datetime.now()
    age = current_date - searched_date
    return age.days


def write_message_in_report(report_file, message):
    with open(report_file, "a") as rf:
        rf.write(f"{message}\n")

def make_request_to_aws(report_file, aws_api, aws_request, test_name):
    
    try:
        output = aws_api.execute(aws_request)
    except AWSCLIError as e:
        write_message_in_report(
            report_file, f"An error ocured while running {test_name}: {e}")
    else:
        return output
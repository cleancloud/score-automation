const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsIam21 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for AWS Management Console authentication failures";
    }

    getFilterPattern() {
        return "{($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\")}";
    }

    getFilterName() {
        return "ConsoleSigninFailure";
    }

    getMetricName() {
        return "ConsoleSigninFailureCount";
    }

    getAlarmName() {
        return "ConsoleSigninFailureAlarm";
    }

    getAlarmDescription() {
        return "Alarm for ConsoleSigninFailure";
    }

    getThreshold() {
        return "3";
    }
}

const execute = async (event) => {
    await new CheckAwsIam21().execute(event);
};

module.exports = { execute };
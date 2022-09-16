const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsIam27 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for unauthorized API calls";
    }

    getFilterPattern() {
        return "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}";
    }

    getFilterName() {
        return "AuthorizationFailure";
    }

    getMetricName() {
        return "AuthorizationFailureCount";
    }

    getAlarmName() {
        return "AuthorizationFailureAlarm";
    }

    getAlarmDescription() {
        return "Alarm for AuthorizationFailure";
    }

    getThreshold() {
        return "3";
    }
}

const execute = async (event) => {
    await new CheckAwsIam27().execute(event);
};

module.exports = { execute };
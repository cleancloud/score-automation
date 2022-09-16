const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsIam26 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for management console sign-in without MFA";
    }

    getFilterPattern() {
        return "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\")}";
    }

    getFilterName() {
        return "ConsoleSignInWithoutMfa";
    }

    getMetricName() {
        return "ConsoleSignInWithoutMfaCount";
    }

    getAlarmName() {
        return "ConsoleSignInWithoutMfaAlarm";
    }

    getAlarmDescription() {
        return "Alarm for ConsoleSignInWithoutMfa";
    }

    getThreshold() {
        return "3";
    }
}

const execute = async (event) => {
    await new CheckAwsIam26().execute(event);
};

module.exports = { execute };
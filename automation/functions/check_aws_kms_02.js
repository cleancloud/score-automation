const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsKms02 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for deletion of CMKs";
    }

    getFilterPattern() {
        return "{($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion))}";
    }

    getFilterName() {
        return "AWSCMKChanges";
    }

    getMetricName() {
        return "AWSCMKChanges";
    }

    getAlarmName() {
        return "AWSCMKChangesAlarm";
    }

    getAlarmDescription() {
        return "Alarm for AWSCMKChanges";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsKms02().execute(event);
};

module.exports = { execute };
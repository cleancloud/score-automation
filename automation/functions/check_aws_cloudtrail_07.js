const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsCloudTrail07 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for CloudTrail configuration changes";
    }

    getFilterPattern() {
        return "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail)" +
                        " || ($.eventName = StartLogging) || ($.eventName = StopLogging)}";
    }

    getFilterName() {
        return "CloudTrailEvent";
    }

    getMetricName() {
        return "CloudTrailEventCount";
    }

    getAlarmName() {
        return "CloudTrailEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for CloudTrailEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsCloudTrail07().execute(event);
};

module.exports = { execute };
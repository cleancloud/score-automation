const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsConfig01 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for AWS Config configuration changes";
    }

    getFilterPattern() {
        return "{($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel)" +
                        " || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder))}";
    }

    getFilterName() {
        return "ConfigEvent";
    }

    getMetricName() {
        return "ConfigEventCount";
    }

    getAlarmName() {
        return "ConfigEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for ConfigEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsConfig01().execute(event);
};

module.exports = { execute };
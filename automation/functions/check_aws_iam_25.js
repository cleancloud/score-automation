const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsIam25 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for usage of root account";
    }

    getFilterPattern() {
        return "{$.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\"}";
    }

    getFilterName() {
        return "RootAccountUsageEvent";
    }

    getMetricName() {
        return "RootAccountUsageEventCount";
    }

    getAlarmName() {
        return "RootAccountUsageEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for RootAccountUsageEvent";
    }

    getThreshold() {
        return "3";
    }
}

const execute = async (event) => {
    await new CheckAwsIam25().execute(event);
};

module.exports = { execute };
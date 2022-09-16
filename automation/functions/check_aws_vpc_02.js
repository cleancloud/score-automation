const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsVpc02 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for NACL changes";
    }

    getFilterPattern() {
        return "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry)" +
                " || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry)" +
                " || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}";
    }

    getFilterName() {
        return "NetworkAclEvent";
    }

    getMetricName() {
        return "NetworkAclEventCount";
    }

    getAlarmName() {
        return "NetworkAclEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for NetworkAclEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsVpc02().execute(event);
};

module.exports = { execute };
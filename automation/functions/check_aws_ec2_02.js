const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsEc202 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for security group changes";
    }

    getFilterPattern() {
        return  "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress)" +
                        " || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress)" +
                        " || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}";
    }

    getFilterName() {
        return "SecurityGroupEvent";
    }

    getMetricName() {
        return "SecurityGroupEventCount";
    }

    getAlarmName() {
        return "SecurityGroupEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for SecurityGroupEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsEc202().execute(event);
};

module.exports = { execute };
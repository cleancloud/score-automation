const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsIam23 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for IAM policy changes";
    }

    getFilterPattern() {
        return "{($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy)" +
                " || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy)" +
                " || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion)" +
                " || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy)" +
                " || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy)" +
                " || ($.eventName = DetachGroupPolicy)}";
    }

    getFilterName() {
        return "IAMPolicyEvent";
    }

    getMetricName() {
        return "IAMPolicyEventCount";
    }

    getAlarmName() {
        return "IAMPolicyEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for IAMPolicyEvent";
    }

    getThreshold() {
        return "3";
    }
}

const execute = async (event) => {
    await new CheckAwsIam23().execute(event);
};

module.exports = { execute };
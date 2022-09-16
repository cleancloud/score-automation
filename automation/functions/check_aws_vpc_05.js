const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsVpc05 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for VPC changes";
    }

    getFilterPattern() {
        return "{($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute)" +
                        " || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection)" +
                        " || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection)" +
                        " || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc)" +
                        " || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink)}";
    }

    getFilterName() {
        return "VpcEvent";
    }

    getMetricName() {
        return "VpcEventCount";
    }

    getAlarmName() {
        return "VpcEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for VpcEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsVpc05().execute(event);
};

module.exports = { execute };
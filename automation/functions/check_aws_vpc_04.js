const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsVpc04 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for route table changes";
    }

    getFilterPattern() {
        return "{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable)" +
                        " || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation)" +
                        " || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute)" +
                        " || ($.eventName = DisassociateRouteTable)}";
    }

    getFilterName() {
        return "RouteTableEvent";
    }

    getMetricName() {
        return "RouteTableEventCount";
    }

    getAlarmName() {
        return "RouteTableEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for RouteTableEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsVpc04().execute(event);
};

module.exports = { execute };
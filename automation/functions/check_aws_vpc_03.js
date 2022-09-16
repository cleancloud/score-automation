const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsVpc03 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for changes to network gateways";
    }

    getFilterPattern() {
        return "{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway)" +
                " || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) " +
                "|| ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)}";
    }

    getFilterName() {
        return "GatewayEvent";
    }

    getMetricName() {
        return "GatewayEventCount";
    }

    getAlarmName() {
        return "GatewayEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for GatewayEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsVpc03().execute(event);
};

module.exports = { execute };
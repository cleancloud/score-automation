const LogMetricAlarm = require("./check_aws_iam_log_metric_alarm");

class CheckAwsS301 extends LogMetricAlarm {

    getDescription() {
        return "Remediate function for missing log metric filter and alarm for S3 bucket policy changes";
    }

    getFilterPattern() {
        return "{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl)" +
                        " || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors)" +
                        " || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication)" +
                        " || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors)" +
                        " || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication))}";
    }

    getFilterName() {
        return "S3BucketEvent";
    }

    getMetricName() {
        return "S3BucketEventCount";
    }

    getAlarmName() {
        return "S3BucketEventAlarm";
    }

    getAlarmDescription() {
        return "Alarm for S3BucketEvent";
    }

    getThreshold() {
        return "1";
    }
}

const execute = async (event) => {
    await new CheckAwsS301().execute(event);
};

module.exports = { execute };
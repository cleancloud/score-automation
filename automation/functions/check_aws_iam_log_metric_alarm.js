const CheckAws = require('./check_aws');
const AWS = require("aws-sdk");

class LogMetricAlarm extends CheckAws {

    constructor() {
        super();
        this.cloudWatchLogs = undefined;
        this.sns = undefined;
        this.cloudWatch = undefined;
    }

    set region(region) {
        this.cloudWatchLogs = new AWS.CloudWatchLogs({region});
        this.sns = new AWS.SNS({region});
        this.cloudWatch = new AWS.CloudWatch({region});
    }

    invokeRemediation = async (event, resource) => {
        this.region = resource["Region"];
        return await this.createLogMetricAlarm(event, resource);
    };

    createLogMetricAlarm(event, resource) {
        const params = JSON.parse(resource["Details"]["Other"]["Params"].replace(/'/g, '"'));
        params.region = resource["Region"]
        const self = this;
        return new Promise((resolve, reject) => {
            var topicArn = "";
            this.putMetricFilter(event, params)
                .then((results) => this.snsCreateTopic(event, params))
                .then((results) => new Promise((resolve, reject) => {
                    topicArn = JSON.parse(JSON.stringify(results, null, 2)).TopicArn;
                    this.snsSubscribe(event, params, topicArn).then(() => resolve(results))
                 }))
                .then((results) => this.putMetricAlarm(event, params, topicArn))
                .then((results) => resolve(results))
            .catch((err) => {
                reject(err);
            });
        });
    };

    putMetricFilter(event, resource) {
        const self = this;
        const params = {
            filterName: self.getFilterName(),
            filterPattern: self.getFilterPattern(),
            logGroupName: resource.LogGroupName,
            metricTransformations: [
                {
                    metricName: self.getMetricName(),
                    metricNamespace: "CloudTrailMetrics",
                    metricValue: "1"
                },
            ]
        };

        return new Promise((resolve, reject) => {
            this.cloudWatchLogs.putMetricFilter(params, (err, results) => {
                if (err) {
                    reject(err);
                }
                else {
                    const msg = `Metric filter [${params.filterName}] created/updated successfully: ${results}`;
                    self.logMessage(event.results, msg);
                    resolve(results);
                }
            });
        });
    };

    snsCreateTopic(event, resource) {
        const self = this;
        const params = {
            Name: resource.TopicName,
            Tags: resource.TopicTags ? resource.TopicTags : []
        };

        return new Promise((resolve, reject) => {
            this.sns.createTopic(params, (err, results) => {
                if (err) {
                    reject(err);
                }
                else {
                    const parsedResults = JSON.stringify(results, null, 2);
                    const msg = `Topic sns [${JSON.parse(JSON.stringify(results, null, 2)).TopicArn}] successfully created/obtained`;
                    self.logMessage(event.results, msg);
                    resolve(results);
                }
            });
        });
    };

    snsSubscribe(event, resource, topicArn) {
        const self = this;
        var params = {
            Protocol: "email",
            TopicArn: topicArn,
            Endpoint: resource.SubscribeEndpoint,
            ReturnSubscriptionArn: true
        };

        return new Promise((resolve, reject) => {
            this.sns.subscribe(params, (err, results) => {
                if (err) {
                    reject(err);
                }
                else {
                    const msg = `SNS endpoint [${params.Endpoint}] successfully subscribed: ${results}`;
                    self.logMessage(event.results, msg);
                    resolve(results);
                }
            });
        });
    };

    putMetricAlarm(event, resource, topicArn) {
        const self = this;
        var params = {
            AlarmName: self.getAlarmName(),
            ComparisonOperator: "GreaterThanOrEqualToThreshold",
            MetricName: self.getMetricName(),
            AlarmDescription: self.getAlarmDescription(),
            Statistic: "Sum",
            Period: 300,
            Threshold: self.getThreshold(),
            AlarmActions: [topicArn],
            EvaluationPeriods: 1,
            Namespace: "CloudTrailMetrics"
        };

        return new Promise((resolve, reject) => {
            this.cloudWatch.putMetricAlarm(params, (err, results) => {
                if (err) {
                    reject(err);
                }
                else {
                    const msg = `Alarm [${params.AlarmName}] successfully created: ${results}`;
                    self.logMessage(event.results, msg);
                    resolve(results);
                }
            });
        });
    };
}

module.exports = LogMetricAlarm;
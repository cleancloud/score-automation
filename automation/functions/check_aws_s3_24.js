const CheckAws = require('./check_aws');
const AWS = require("aws-sdk");

class CheckAwsS324 extends CheckAws {

    getDescription () {
        return "Remediate function for S3 buckets with unrestricted DELETE action"
    }

    constructor() {
        super();
        this.s3 = undefined;
    }

    set region(region) {
        this.s3 = new AWS.S3({region});
    }

    invokeRemediation = async (event, resource) => {
        this.region = this.getResourceRegion(event, resource);
        const self = this;
        return await new Promise((resolve, reject) => {

            const params = {
                Bucket: resource.Id,
            };

            this.s3.getBucketPolicy(params, (err, results) => {
                if (err) {
                    if (err["code"] === 'NoSuchBucketPolicy') {
                        const msg = `Policy from bucket [${params.Bucket}] already cleaned.`;
                        self.logMessage(event.results, msg);
                        return resolve(msg);
                    }
                    return reject(err);
                }
                else {
                    const policies = JSON.parse(results["Policy"]);
                    self.logMessage(event.results, "Initial policy:\n" + JSON.stringify(policies, null, 2));

                    var policiesToRemove = [];
                    var totalPolicies = 0;
                    for (var policyIndex in policies["Statement"]) {
                        const policy = policies["Statement"][policyIndex];
                        if (policy["Effect"] === "Allow" && policy["Principal"] === "*" && policy["Action"].startsWith("s3:Delete")) {
                            policiesToRemove.push(policyIndex);
                        }
                        totalPolicies++;
                    }

                    if (policiesToRemove.length == 0) {
                        const msg = `Policy from bucket [${params.Bucket}] does not need to be changed.`;
                        self.logMessage(event.results, msg);
                        return resolve(msg);
                    }

                    var deletePolicy = policiesToRemove.length === totalPolicies;
                    policiesToRemove.forEach(policyIndex => {
                        policies["Statement"].splice(policyIndex, 1);
                    })

                    self.logMessage(event.results, "Final policy:\n" + JSON.stringify(policies, null, 2));
                    if (deletePolicy) {
                        const params = {
                            Bucket: resource.Id
                        };
                        this.s3.deleteBucketPolicy(params, function(err, results) {
                            if (err) {
                                return reject(err);
                            } else {
                                const msg = `Policy from bucket [${params.Bucket}] deleted successfully`;
                                self.logMessage(event.results, msg);
                                return resolve(msg);
                            }
                        });
                    } else {
                        const params = {
                            Bucket: resource.Id,
                            Policy: JSON.stringify(policies, null, 2)
                        };
                        this.s3.putBucketPolicy(params, function(err, results) {
                            if (err) {
                                return reject(err);
                            } else {
                                const msg = `Policy from bucket [${params.Bucket}] changed successfully`;
                                self.logMessage(event.results, msg);
                                return resolve(msg);
                            }
                        });
                    }
                }
            });
        });
    };
}

const execute = async (event) => {
    await new CheckAwsS324().execute(event);
};

module.exports = { execute };

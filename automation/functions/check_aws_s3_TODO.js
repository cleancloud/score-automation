const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");
const s3 = new AWS.S3();

class CheckAwsS3TODO extends CheckAws {

    getDescription () {
        return "Remediate function for S3 buckets with public access"
    }

    invokeRemediation = async (event, resource) => {
        const self = this;
        return await new Promise((resolve, reject) => {
            const params = {
                Bucket: resource.Id,
                PublicAccessBlockConfiguration: {
                    BlockPublicAcls: true,
                    BlockPublicPolicy: true,
                    IgnorePublicAcls: true,
                    RestrictPublicBuckets: true
                }
            };

            s3.putPublicAccessBlock(params, (err, results) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve("Public access was blocked successfully on [" + params.Bucket + "] bucket. Results: " + JSON.stringify(results));
                }
            });
        });
    };
};

const execute = async (event) => {
    await new CheckAwsS3TODO().execute(event);
};

module.exports = { execute };

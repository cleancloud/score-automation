const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");
// In case of local test, if code complains about missing region, insert the line below:
// AWS.config.update({region:'us-east-1'});
const ec2 = new AWS.EC2();

class CheckAwsEC209 extends CheckAws {

    getDescription () {
        return "Remediate function for EBS snapshots with unrestricted access"
    }

    invokeRemediation = async (event, resource) => {
        const self = this;
        return await new Promise((resolve, reject) => {
            const params = {
                Attribute: "createVolumePermission",
                GroupNames: ["all"],
                OperationType: "remove",
                SnapshotId: resource.Id
            };
            
            self.logMessage(event.results, "Params:" + JSON.stringify(params));
            
            ec2.modifySnapshotAttribute(params, function (err, results) {
                if (err) reject(err);
                else resolve(results);
            });
        });
    };
};

const execute = async (event) => {
    await new CheckAwsEC209().execute(event);
};

module.exports = { execute };

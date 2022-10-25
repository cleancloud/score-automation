const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");

class CheckAwsEC209 extends CheckAws {

    constructor() {
        super();
        this.ec2 = undefined;
    }

    set region(region) {
        this.ec2 = new AWS.EC2({region});
    }

    getDescription () {
        return "Remediate function for EBS snapshots with unrestricted access"
    }

    invokeRemediation = async (event, resource) => {
        this.region = this.getResourceRegion(event, resource);
        const self = this;
        return await new Promise((resolve, reject) => {
            const params = {
                Attribute: "createVolumePermission",
                GroupNames: ["all"],
                OperationType: "remove",
                SnapshotId: resource.Id
            };
            
            self.logMessage(event.results, "Params:" + JSON.stringify(params));
            
            this.ec2.modifySnapshotAttribute(params, function (err, results) {
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

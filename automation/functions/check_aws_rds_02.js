const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");

class CheckAwsRDS02 extends CheckAws {

    getDescription () {
        return "Remediate function for RDS with unrestricted access"
    }

    constructor() {
        super();
        this.rds = undefined;
    }

    set region(region) {
        this.rds = new AWS.RDS({region});
    }

    invokeRemediation = async (event, resource) => {
        this.region = this.getResourceRegion(event, resource);
        return await this.modifyDBInstance(event, resource);
    };

    modifyDBInstance = async (event, resource) => {
        const self = this;
        return await new Promise((resolve, reject) => {
            const params = {
                DBInstanceIdentifier: resource["Details"]["Other"]["dbInstanceIdentifier"],
                PubliclyAccessible: false
            };

            self.logMessage(event.results, "Params:" + JSON.stringify(params, null, 2));

            this.rds.modifyDBInstance(params, function (err, results) {
                if (err) {
                    reject(err);
                }
                else {
                    const parsedResults = JSON.stringify(results, null, 2);
                    const msg = `Rds [${params.DBInstanceIdentifier}] successfully changed`;
                    self.logMessage(event.results, msg);
                    resolve(results);
                }
            });
        });
    };
};

const execute = async (event) => {
    await new CheckAwsRDS02().execute(event);
};

module.exports = { execute };

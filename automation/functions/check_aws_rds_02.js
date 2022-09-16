const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");
// In case of local test, if code complains about missing region, insert the line below:
// AWS.config.update({region:'us-east-1'});
const rds = new AWS.RDS();

class CheckAwsRDS02 extends CheckAws {

    getDescription () {
        return "Remediate function for RDS with unrestricted access"
    }

    invokeRemediation = async (event, resource) => {
        const self = this;
        return await new Promise((resolve, reject) => {
            const params = {
                DBInstanceIdentifier: resource.Id,
                PubliclyAccessible: false
            };
            
            self.logMessage(event.results, "Params:" + JSON.stringify(params));

            rds.modifyDBInstance(params, function (err, results) {
                if (err) reject(err);
                else resolve(results);
            });
        });
    };
};

const execute = async (event) => {
    await new CheckAwsRDS02().execute(event);
};

module.exports = { execute };

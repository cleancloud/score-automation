const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");

class CheckAwsEC213 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for security groups with unrestricted entry rules"
    }

    changeRules (resource) {
        const self = this;
        return new Promise((resolve, reject) => {
            this.ec2.describeSecurityGroupRules(self.getDescribeParams(resource.Id), (err, results) => {
                if (err) reject(err);
                else {
                    resolve(
                        results["SecurityGroupRules"].map(rule => {
                            if (rule["IsEgress"] == false) {
                                return self.changeRulesByIpVersion(resource, rule);
                            }
                            else {
                                return true;
                            }
                        }).flat()
                    );
                };
            });
        });
    };
};

const execute = async (event) => {
    await new CheckAwsEC213().execute(event);
};

module.exports = { execute };
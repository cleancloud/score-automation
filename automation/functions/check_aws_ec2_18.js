const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");

class CheckAwsEC218 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for HTTPS with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [443],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC218().execute(event);
};

module.exports = { execute };
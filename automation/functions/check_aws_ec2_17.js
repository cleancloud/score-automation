const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");

class CheckAwsEC217 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for HTTP with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [80],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC217().execute(event);
};

module.exports = { execute };
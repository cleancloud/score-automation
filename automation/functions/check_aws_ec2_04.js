const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");

class CheckAwsEC204 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for RDP with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [3389],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC204().execute(event);
};

module.exports = { execute };

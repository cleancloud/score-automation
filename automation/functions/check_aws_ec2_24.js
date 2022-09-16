const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");
const ec2 = new AWS.EC2();

class CheckAwsEC224 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for SMTP with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [25],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC224().execute(event);
};

module.exports = { execute };
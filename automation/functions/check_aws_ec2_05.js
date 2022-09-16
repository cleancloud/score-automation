const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");
const ec2 = new AWS.EC2();

class CheckAwsEC205 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for SSH with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [22],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC205().execute(event);
};

module.exports = { execute };
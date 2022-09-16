const Ec2SecurityGroupRules = require("./check_aws_ec2_security_group_rules");
const AWS = require("aws-sdk");
const ec2 = new AWS.EC2();

class CheckAwsEC227 extends Ec2SecurityGroupRules {

    getDescription () {
        return "Remediate function for FTP with unrestricted access"
    }

    getSgRestrictions(ports, protocol) {
        return ({
                    Ports: [20, 21],
                    IpProtocol: "tcp"
                })
    };
};

const execute = async (event) => {
    await new CheckAwsEC227().execute(event);
};

module.exports = { execute };
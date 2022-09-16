const CheckAws = require("./check_aws");
const AWS = require("aws-sdk");
const ec2 = new AWS.EC2();

class Ec2SecurityGroupRules extends CheckAws {

    getDescribeParams(resourceId) {
        return ({
                   Filters: [{
                       Name: "group-id",
                       Values: [resourceId]
                   }]
               })
    };

    deleteRule(resourceId, securityGroupRuleId) {
        const delete_params = {
            GroupId: resourceId,
            SecurityGroupRuleIds: [
                securityGroupRuleId
            ]
        };

        return new Promise((resolve, reject) => {
            ec2.revokeSecurityGroupIngress(delete_params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
    };

    createRule(create_params) {
        return new Promise((resolve, reject) => {
            ec2.authorizeSecurityGroupIngress(create_params, (err, results) => {
                if (err) reject(err);
                else resolve(results);
            });
        });
    };

    getParamsBySourceType(resourceId, rule, newPermissionAddress, type) {
        switch (type) {
            case "securityGroup":
                return {
                    GroupId: resourceId,
                    IpPermissions: [{
                        FromPort: rule["FromPort"],
                        IpProtocol: rule["IpProtocol"],
                        UserIdGroupPairs: [{
                            Description: rule["Description"] ? rule["Description"] : "",
                            GroupId: newPermissionAddress
                        }],
                        ToPort: rule["ToPort"]
                    }]
                };

            case "prefixList":
                return {
                    GroupId: resourceId,
                    IpPermissions: [{
                        FromPort: rule["FromPort"],
                        IpProtocol: rule["IpProtocol"],
                        PrefixListIds: [{
                            Description: rule["Description"] ? rule["Description"] : "",
                            PrefixListId: newPermissionAddress
                        }],
                        ToPort: rule["ToPort"]
                    }]
                };

            case "ipv4":
                return {
                    GroupId: resourceId,
                    IpPermissions: [{
                        FromPort: rule["FromPort"],
                        IpProtocol: rule["IpProtocol"],
                        IpRanges: [{
                            Description: rule["Description"] ? rule["Description"] : "",
                            CidrIp: newPermissionAddress
                        }],
                        ToPort: rule["ToPort"]
                    }]
                };

            case "ipv6":
                return {
                    GroupId: resourceId,
                    IpPermissions: [{
                        FromPort: rule["FromPort"],
                        IpProtocol: rule["IpProtocol"],
                        Ipv6Ranges: [{
                            Description: rule["Description"] ? rule["Description"] : "",
                            CidrIpv6: newPermissionAddress
                        }],
                        ToPort: rule["ToPort"]
                    }]
                };
        }
    };

    createRulePerSourceType(param, resourceId, rule) {
        var results = [];
        if (param["To"]){
             if (param["To"]["securityGroup"]) {
                 results = results.concat(param["To"]["securityGroup"].map(securityGroup =>
                     this.createRule(this.getParamsBySourceType(resourceId, rule, securityGroup, "securityGroup"))
                ));
             }
             if (param["To"]["prefixList"]) {
                results = results.concat(param["To"]["prefixList"].map(prefixList =>
                    this.createRule(this.getParamsBySourceType(resourceId, rule, prefixList, "prefixList"))
                ));
             }
             if (param["To"]["ipv4"]) {
                 results = results.concat(param["To"]["ipv4"].map(ipv4 =>
                     this.createRule(this.getParamsBySourceType(resourceId, rule, ipv4, "ipv4"))
                 ));
             }
             if (param["To"]["ipv6"]) {
                 results = results.concat(param["To"]["ipv6"].map(ipv6 =>
                     this.createRule(this.getParamsBySourceType(resourceId, rule, ipv6, "ipv6"))
                 ));
             }
        };
        return results;
    }

    changeRulesByIpVersion(resource, rule) {
        var results = [];
        if (rule["CidrIpv4"] ? rule["CidrIpv4"] == "0.0.0.0/0" : false) {
            results = results.concat(this.deleteRule(resource.Id, rule["SecurityGroupRuleId"]));
            JSON.parse(resource["Details"]["Other"]["Params"].replace(/'/g, '"')).forEach(param => {
                if (param["From"] == "0.0.0.0/0") {
                    results = results.concat(this.createRulePerSourceType(param, resource.Id, rule)).flat();
                };
            });
        };
        if (rule["CidrIpv6"] ? (rule["CidrIpv6"] == "::/0" || rule["CidrIpv6"] == ":0:0:0:0:0:0:0/0") : false) {
            results = results.concat(this.deleteRule(resource.Id, rule["SecurityGroupRuleId"]));
            JSON.parse(resource["Details"]["Other"]["Params"].replace(/'/g, '"')).forEach(param => {
                if (param["From"] == "::/0" || param["From"] == ":0:0:0:0:0:0:0/0") {
                    results = results.concat(this.createRulePerSourceType(param, resource.Id, rule)).flat();
                };
            });
        };
        return results;
    }

    changeRules(resource) {
        const self = this;
        const sgRestrictions = self.getSgRestrictions()
        return new Promise((resolve, reject) => {
            ec2.describeSecurityGroupRules(self.getDescribeParams(resource.Id), (err, results) => {
                if (err) reject(err);
                else {
                    resolve(
                        results["SecurityGroupRules"].map(rule => {
                            if (rule["IsEgress"] == false && (rule["IpProtocol"] == '-1' || rule["IpProtocol"] == sgRestrictions["IpProtocol"])
                                && (rule["FromPort"] == -1 || sgRestrictions["Ports"].some(port => { return (rule["FromPort"] <= port && rule["ToPort"] >= port);}))) {
                                return self.changeRulesByIpVersion(resource, rule);
                            } else {
                                return true;
                            }
                        }).flat()
                    );
                };
            });
        });
    };

    invokeRemediation = async (event, resource) => {
        return await Promise.all(await this.changeRules(resource));
    };
}

module.exports = Ec2SecurityGroupRules;
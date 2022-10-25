class CheckAws {

    invokeRemediation = async (event, resource) => {
        throw this._WARNING("invokeRemediation");
    }

    getDescription () {
        throw this._WARNING("getDescription");
    }

    logMessage (results, msg) {
        results.push(msg);
        console.info(msg);
    }

    getResourceRegion (event, resource) {
        return resource["Region"] && resource["Region"].toUpperCase() !== "N/A" ? resource["Region"] : event.region;
    }

    validateResults = (event) => {
        if (!event || !event.results) {
            throw new Error("Suppress remediation: Results not specified");
        }
    };

    validatePayload = (event) => {
        this.logMessage(event.results, 'Validate parameters.');
        if (!event.payload || !JSON.parse(event.payload).Id) {
            throw new Error("Suppress remediation: Id not specified");
        }
        return JSON.parse(event.payload);
    };

    execute = async (event) => {
        return await new Promise((resolve, reject) => {
            const msg = `Started remediation function for event [\n ${JSON.stringify(event, null, 2)}]`;
            console.info(msg);

            try {
                this.validateResults(event);
                event.results.push(msg);
            } catch (err) {
                console.info(err);
                reject(`Error on validate results parameter: ${err}`);
            }

            var payload = {};
            try {
                payload = this.validatePayload(event);
            } catch (err) {
                console.info(err);
                reject(`Error on validate parameters: ${err}`);
            }

            this.logMessage(event.results, this.getDescription());

            this.invokeRemediation(event, payload).then((success) => {
                resolve(success);
            }).catch((err) => {
                console.info(err);
                reject(err);
            });
        });
    };

    // declare a warning generator to notice if a method of the interface is not overridden
    _WARNING(fName='unknown method') {
        console.warn('WARNING! Function "'+fName+'" is not overridden in '+this.constructor.name);
    }
}

module.exports = CheckAws;

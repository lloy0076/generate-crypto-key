const App = require('./lib/App');
const logger = require('./lib/Logger');

const main = new App(logger);

main.run().catch((error) => {
    logger.error(error.message);
    logger.silly('Error %s', error);
});

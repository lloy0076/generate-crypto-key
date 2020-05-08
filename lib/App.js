const crypto = require('crypto');
const fs = require('fs');
const moment = require('moment');

const Boom = require('@hapi/boom');
const GetOpt = require('node-getopt');
const Joi = require('@hapi/joi');
const CustomJoi = Joi.extend((joi) => {
    return {
        type: 'file',
        base: joi.string(),
        messages: {
            'file.invalid': 'the file name may not be empty',
            'file.absent': 'the file "{{#value}}" must not exist',
        },
        validate(value, helpers) {
            if (!value || !value.length) {
                return helpers.error('file.invalid');
            }
        },
        rules: {
            absent: {
                validate(value, helpers, args, options) {
                    try {
                        fs.accessSync(value);
                        return helpers.error('file.absent', { value });
                    } catch (err) {
                        // Don't forget to return the value or you'll get the default!
                        return value;
                    }
                }
            },
        }
    };
});

const defaultBits = 2048;
const allowedCiphers = ['rsa', 'dsa', 'ec', 'ed25519', 'ed448', 'x25519', 'x448', 'dh'];

class App {
    constructor(customLogger) {
        // eslint-disable-next-line global-require
        this.logger = customLogger || require('./Logger');

        this.keyOptions = {
            algorithm: 'rsa',
            bits: defaultBits,
            divisorLength: null,
            namedCurve: null,
            prime: null,
            generator: 2, // -- the default
            groupName: null,
            publicExponent: 0x1001, // 4097 -- the default
            publicKeyFile: 'public.key',
            publicKeyFormat: 'pem',
            publicKeyEncoding: 'spki',
            privateKeyCipher: 'aes-256-cbc',
            privateKeyEncoding: 'pkcs8',
            privateKeyFile: 'private.key',
            privateKeyFormat: 'pem',
        };
    }

    async run() {
        this.logger.debug(`Starting at ${moment().format()}.`);

        this.getOptions();
        this.validateOptions();

        this.logger.silly('%s %s', this.argv, this.options);
        this.logger.silly('Key options: %s', this.keyOptions);

        this.execute();

        this.logger.debug(`Ending at ${moment().format()}.`);
    }

    /**
     * Gets the options:
     *
     * - file The file (must end in .csv)
     * - help The help
     * .
     */
    getOptions() {
        const getopt = new GetOpt([
            ['a', 'algorithm=rsa', 'the algorithm (defaults to "rsa")'],
            ['b', 'bits=2048', 'the number of bits (defaults to "2048")'],
            ['c', 'curve=curve25519', 'the named curve'],
            ['d', 'divisorLength=2', 'the divisor length'],
            ['e', 'exponent=4097', 'the public key exponent (defaults to "0x10001" / "4097")'],
            ['g', 'generator=2', 'the generator (defaults to "2")'],
            ['n', 'name=24', 'the group name (defaults to "24")'],
            ['', 'stdout', 'write to stdout'],
            ['p', 'passphrase=abracadabra', 'the passphrase'],
            ['', 'privateKeyCipher=aes-256-cbc', 'the private key cipher'],
            ['', 'privateKeyEncoding=pkcs8', 'the private key encoding'],
            ['q', 'privateKeyFile=private.key', 'the private key file; will NOT be overwritten'],
            ['', 'privateKeyFormat=pem', 'the private key format'],
            ['', 'publicKeyEncoding=spki', 'the public key encoding'],
            ['r', 'publicKeyFile=public.key', 'the private key file; will NOT be overwritten'],
            ['', 'publicKeyFormat=pem', 'the public key format'],
            ['h', 'help', 'display this help\n\n\tNOTE:\n\n\t'
            + 'When setting parameters YOU are responsible for ensuring the keys generated\n\tsatisfy any of your security '
            + 'requirements; any defaults are SUGGESTIONS only.'],
        ]);

        // noinspection JSUnresolvedFunction
        const { argv, options } = getopt.bindHelp().parseSystem();

        this.argv = argv;
        this.options = { ...this.keyOptions, ...options };
    }

    /**
     * Validates the options.
     *
     * - the file option must not be empty, must end in .csv and must be readable.
     * .
     *
     * @return {boolean}
     */
    validateOptions() {
        const cipherRe = new RegExp(`^(?:${allowedCiphers.join('|')})$`);
        const shape = {
            algorithm: CustomJoi.string().regex(cipherRe).default('rsa'),
            bits: CustomJoi.number().integer().min(512).default(512),
            curve: CustomJoi.string().default('curve25519'),
            exponent: CustomJoi.number().integer().default(0x1001),
            generator: CustomJoi.number().integer().default(2),
            name: CustomJoi.string().default('24'),
            passphrase: CustomJoi.string().default('abracadabra'),
            publicKeyEncoding: CustomJoi.string().regex(/^spki$/).default('spki'),
            publicKeyFile: CustomJoi.file().absent().default('public.key'),
            publicKeyFormat: CustomJoi.string().regex(/^pem$/).default('pem'),
            privateKeyCipher: CustomJoi.string().regex(/^aes-256-cbc$/).default('aes-256-cbc'),
            privateKeyEncoding: CustomJoi.string().regex(/^pkcs8$/).default('pkcs8'),
            privateKeyFile: CustomJoi.file().absent().default('private.key'),
            privateKeyFormat: CustomJoi.string().regex(/^pem$/).default('pem'),
        };

        const schema = CustomJoi.object().keys(shape).unknown(true);

        this.logger.silly('Options at start', { options: this.options });
        const result = schema.validate(this.options);

        if (result.error) {
            result.error.details.forEach((error) => {
                this.logger.debug('%s: %s', error.path, error.message);
                this.logger.silly('Error Context', { context: error.context });
                throw new Boom.preconditionFailed(`The option "--${error.context.label}" is invalid:\n\t${error.message}`);
            });

            throw new Boom.preconditionFailed('There was an error validating the options.');
        }

        this.logger.silly('Result', { result: result.value });

        this.options = { ...this.options, ...result.value };
        this.keyOptions = this.options;

        return true;
    }

    /**
     * Perform the action.
     *
     * @return {boolean}
     */
    execute() {
        if (this.options.algorithm === 'rsa') {
            const options = {
                modulusLength: this.options.bits,
                publicKeyEncoding: {
                    type: this.options.publicKeyEncoding,
                    format: this.options.publicKeyFormat,
                },
                privateKeyEncoding: {
                    type: this.options.privateKeyEncoding,
                    format: this.options.privateKeyFormat,
                    cipher: this.options.privateKeyCipher,
                    passphrase: this.options.passphrase,
                },
            };

            crypto.generateKeyPair(this.options.algorithm, options, (err, publicKey, privateKey) => {
                if (err) {
                    this.logger.error('Error %s', err);
                    this.logger.debug('Error Details', { error: err });
                } else {
                    try {
                        this.logger.info('Writing public key to "%s"...', this.options.publicKeyFile);
                        fs.writeFileSync(this.options.publicKeyFile, publicKey);

                        this.logger.info('Writing private key to "%s"...', this.options.privateKeyFile);
                        fs.writeFileSync(this.options.privateKeyFile, privateKey);
                    } catch (err) {
                        throw new Boom.Boom(err);
                    }
                }
            });
        } else {
            this.logger.warn('Operation not implemented.');
        }

        return true;
    }
}

module.exports = App;

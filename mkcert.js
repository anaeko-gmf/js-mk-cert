
const fs = require('fs');
const net = require('net');
const path = require('path');
const process = require('process');
const mkKeyPair = require('./keypair');

const CA_ROOT_CRT = 'rootCA.pem.crt';
const CA_ROOT_KEY = 'rootCA.pem.key';
const CERT_ORGANIZATION_NAME = 'js-mk-cert development certificate';
const CERT_ORGANIZATION_UNIT_NAME = 'averagehuman';


let params = process.argv.slice(2);
if (!params || params.length === 0) {
    console.error('A common name is required as input, eg. an IP address or domain name');
    process.exit(1);
}
const CERT_COMMON_NAME = params[0];
const CERT_SUBJECT_ALT_NAME =
    net.isIP(CERT_COMMON_NAME) ? { type: 7, ip: CERT_COMMON_NAME} : { type: 2, value: CERT_COMMON_NAME };

const CERT_SUBJECT_ATTRS = [
    {
        name: 'commonName',
        value: CERT_COMMON_NAME
    },
    {
        name: 'organizationName',
        value: CERT_ORGANIZATION_NAME
    },
    {
        name: 'organizationalUnitName',
        value: CERT_ORGANIZATION_UNIT_NAME
    }
];

const CERT_EXT_ATTRS = [
    {
        name: 'subjectAltName',
        altNames: [CERT_SUBJECT_ALT_NAME]
    }
];


const PRIV_KEY_OUTPUT_FILE = path.resolve(__dirname, CERT_COMMON_NAME + '.key');
const CERT_OUTPUT_FILE = path.resolve(__dirname, CERT_COMMON_NAME + '.crt');

[PRIV_KEY_OUTPUT_FILE, CERT_OUTPUT_FILE].forEach( filename => {
    if (fs.existsSync(filename)) {
        console.error(`Output file exists: ${filename}`);
        process.exit(1);
    }
} );

function main() {
    let caCert;
    let caKey;
    let keypair;

    try {
        caCert = fs.readFileSync(CA_ROOT_CRT, {encoding: 'ascii'});
        caKey = fs.readFileSync(CA_ROOT_KEY, {encoding: 'ascii'});
    } catch (err) {
        console.error(err);
        process.exit(1);
    }

    console.log(`Creating self-signed certificate (CN=${CERT_COMMON_NAME})...`);

    try {
        keypair = mkKeyPair(
            caCert,
            caKey,
            CERT_SUBJECT_ATTRS,
            CERT_EXT_ATTRS
        );
    } catch (err) {
        console.error(err);
        process.exit(1);
    }


    fs.writeFileSync(PRIV_KEY_OUTPUT_FILE, keypair.privateKeyPem);
    console.log(`Wrote file: ${PRIV_KEY_OUTPUT_FILE}`);

    fs.writeFileSync(CERT_OUTPUT_FILE, keypair.certPem);
    console.log(`Wrote file: ${CERT_OUTPUT_FILE}`);
}

main();



const fs = require('fs');
const net = require('net');
const path = require('path');
const process = require('process');
const mkKeyPair = require('./keypair');

const CA_ROOT_CRT = 'rootCA.pem.crt';
const CA_ROOT_KEY = 'rootCA.pem.key';


let params = process.argv.slice(2);
if (!params || params.length === 0) {
    console.error('A common name is required as input, eg. an IP address, dns name, email address');
    process.exit(1);
}
let certCommonName = params[0];
const certOrganizationName = params[1];
const certOrganizationUnitName = params[2];

const certExtAttrs = [
    {
        name: 'basicConstraints',
        cA: false,
        critical: true
    },
    {
        name: 'keyUsage',
        value: 'Digital Signature, Key Encipherment',
        critical: true
    }
];
let certSubjectAttrs;
let certSubjectAltName;
let extKeyUsage;


if (certCommonName.startsWith('client:')) {
    certCommonName = certCommonName.substr('client:'.length);
    if (certCommonName.indexOf('@') > -1) {
        // rfc822Name
        console.debug('rfc822Name');
        certSubjectAltName = {type: 1, value: certCommonName};
    }
    extKeyUsage = 'TLS Web Client Authentication';
} else {
    // derive SAN from CN (eg. ip address or server name)
    // cf. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
    if (net.isIP(certCommonName)) {
        // iPAddress
        certSubjectAltName = { type: 7, ip: certCommonName};
    } else {
        // dNSName
        certSubjectAltName = { type: 2, value: certCommonName };
    }
    extKeyUsage = 'TLS Web Server Authentication';
}

certExtAttrs.push({
    name: 'extKeyUsage',
    value: extKeyUsage
});

if (!!certSubjectAltName) {
    certExtAttrs.push({
        name: 'subjectAltName',
        altNames: [certSubjectAltName]
    });
}

certSubjectAttrs = [
    {
        name: 'commonName',
        value: certCommonName
    }
];

if (!!certOrganizationName) {
    certSubjectAttrs.push({
        name: 'organizationName',
        value: certOrganizationName
    });
}

if (!!certOrganizationUnitName) {
    certSubjectAttrs.push({
        name: 'organizationUnitName',
        value: certOrganizationUnitName
    });
}


const privKeyOutputFile = path.resolve(__dirname, certCommonName + '.key');
const certOutputFile = path.resolve(__dirname, certCommonName + '.crt');

[privKeyOutputFile, certOutputFile].forEach( filename => {
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

    console.log(`Creating self-signed certificate (CN=${certCommonName})...`);

    try {
        keypair = mkKeyPair(
            caCert,
            caKey,
            certSubjectAttrs,
            certExtAttrs
        );
    } catch (err) {
        console.error(err);
        process.exit(1);
    }


    fs.writeFileSync(privKeyOutputFile, keypair.privateKeyPem);
    console.log(`Wrote file: ${privKeyOutputFile}`);

    fs.writeFileSync(certOutputFile, keypair.certPem);
    console.log(`Wrote file: ${certOutputFile}`);
}

main();


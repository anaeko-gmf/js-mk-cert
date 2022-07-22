
const crypto = require('crypto');
const forge = require('node-forge');
const pki = forge.pki;

const DEFAULT_EXPIRY_YEARS = 1;
const DEFAULT_KEY_LENGTH = 2048;

/**
 * Returns a random unique hexidecimal string
 *
 * @param {string=} text - optional namespace
 */
function mkSerialNumber(namespace) {
    const rnd = '.' + new Date() + '.' + Math.floor(Math.random() * 100000);
    const hash = crypto.createHash('sha1').update(namespace + rnd, 'binary');
    // Prepend '00' to prevent negative serial number (https://github.com/digitalbazaar/forge/issues/349)
    return '00' + hash.digest('hex');
}

/**
 * Generate a PKI X.509 certificate and private key signed by the given Certificate Authority key
 *
 * @param {string} caCertPem
 * @param {string} caKeyPem
 * @param {Object[]} subject
 * @param {Object[]} extensions
 * @param {Object=} options
 */
function mkKeyPair(caCertPem, caKeyPem, subject, extensions, options) {

    const opts = {...(options || {})};
    opts.keyLength = opts.keyLength || DEFAULT_KEY_LENGTH;
    opts.expiryYears = opts.expiryYears || DEFAULT_EXPIRY_YEARS;
    opts.serialNumber = opts.serialNumber || mkSerialNumber(JSON.stringify(subject));

    const caCert = pki.certificateFromPem(caCertPem);
    console.debug(caCert);
    const caKey = pki.privateKeyFromPem(caKeyPem);
    const keys = pki.rsa.generateKeyPair(opts.keyLength);
    const cert = pki.createCertificate();
    const currentYear = new Date().getFullYear();
    extensions = extensions || [];
    hasAuthorityKeyId = extensions.some((elem) => elem.name === 'authorityKeyIdentifier');
    if (!hasAuthorityKeyId) {
        const subjectKeyIdentifier = caCert.getExtension('subjectKeyIdentifier');
        if (!!subjectKeyIdentifier) {
            // normalise key - uppercase, split and join with ':'
            const hex = subjectKeyIdentifier.subjectKeyIdentifier.toUpperCase();
            const parts = ['keyid'];
            for (let i=0; i<hex.length; i=i+2) {
                parts.push(hex.substr(i, 2));
            }
            extensions.push({
                name: 'authorityKeyIdentifier',
                value: parts.join(':')
            });
        }
    }

    cert.publicKey = keys.publicKey;
    cert.serialNumber = opts.serialNumber;
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(currentYear + opts.expiryYears);
    cert.setSubject(subject);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions(extensions);

    cert.sign(caKey, forge.md.sha256.create());

    return {
        privateKeyPem: pki.privateKeyToPem(keys.privateKey),
        certPem: pki.certificateToPem(cert)
    }
}

module.exports = mkKeyPair;


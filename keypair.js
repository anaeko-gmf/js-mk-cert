
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
    const caKey = pki.privateKeyFromPem(caKeyPem);
    const keys = pki.rsa.generateKeyPair(opts.keyLength);
    const cert = pki.createCertificate();
    const currentYear = new Date().getFullYear();

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


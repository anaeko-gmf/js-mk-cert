
const crypto = require('crypto');
const forge = require('node-forge');
const pki = forge.pki;

function mkSerialNumber(commonName) {
    const rnd = '.' + new Date() + '.' + Math.floor(Math.random() * 100000);
    const hash = crypto.createHash('sha1').update(commonName + rnd, 'binary');
    // Prepend '00' to prevent negative serial number, cf. https://github.com/digitalbazaar/forge/issues/349
    return '00' + hash.digest('hex');
}

function mkKeyPair(caCertPem, caKeyPem, commonName, expiresAfter, keyLength, subject, ext) {
    const caCert = pki.certificateFromPem(caCertPem);
    const caKey = pki.privateKeyFromPem(caKeyPem);

    const keys = pki.rsa.generateKeyPair(keyLength);
    const cert = pki.createCertificate();
    const currentYear = new Date().getFullYear();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = mkSerialNumber(commonName);
    console.debug(cert.serialNumber);
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(currentYear + expiresAfter);
    cert.setSubject(subject);
    cert.setIssuer(caCert.subject.attributes);
    cert.setExtensions(ext);
    cert.sign(caKey, forge.md.sha256.create());

    return {
        privateKeyPem: pki.privateKeyToPem(keys.privateKey),
        certPem: pki.certificateToPem(cert)
    }
}

module.exports = mkKeyPair;


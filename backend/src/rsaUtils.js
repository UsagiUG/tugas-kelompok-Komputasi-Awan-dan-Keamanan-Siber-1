//https://medium.com/@aifuture/implementing-rsa-encryption-in-a-node-js-application-50bbb78994e7

import crypto from 'crypto'
import config from './config.js'

const {passphrase ,encryption_method} = config
const RSAUtils = {
  // Generate RSA Key Pair
    generateKeyPair: () =>
        new Promise((resolve, reject) => {
        crypto.generateKeyPair(
            'rsa',
            {
            modulusLength: 2048, // Key length
            publicKeyEncoding: { type: 'spki', format: 'pem' }, // Public key encoding
            privateKeyEncoding: { 
                    type: 'pkcs8', 
                    format: 'pem' ,
                }, // Private key encoding
            },
            (err, publicKey, privateKey) => {
                if (err) reject(err);
                resolve({ publicKey, privateKey });
            }
        );
        }),
  // Encrypt Data with Public Key
    encrypt: (publicKey, plaintext) =>
        crypto.publicEncrypt(
            {
                key: publicKey,
            },
            Buffer.from(plaintext)
        ),

// //   Decrypt Data with Private Key
    decrypt: (privateKey, encrypted) => 
        crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
        Buffer.from(encrypted,"base64"))
    ,

    // decrypt: (privateKey, encrypted) => 
    //     crypto.privateDecrypt(privateKey, Buffer.from(encrypted,"base64"))
    // ,

  // Sign Data with Private Key
    sign: (message) => {
        const signer = crypto.createSign('sha256');
        signer.update(message);
        signer.end();
        return signer.sign(privateKey, 'base64');
    },

  // Verify Signature with Public Key
    verify: (publicKey, message, signature) => {
        const verifier = crypto.createVerify('sha256');
        verifier.update(message);
        verifier.end();
        return verifier.verify(publicKey, signature, 'base64');
    },
};

export default RSAUtils
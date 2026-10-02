import crypto from 'crypto';

const ECCUtils = {
    decrypt: (serverPrivateKeyPem, ephemeralPublicKeyBytes) => {
        const serverPrivate = crypto.createPrivateKey(serverPrivateKeyPem);
        const ephemeralPublic = crypto.createPublicKey({
            key: Buffer.from(ephemeralPublicKeyBytes, 'base64'),
            format: 'der',
            type: 'spki'
        });

        const sharedSecret = crypto.diffieHellman({
            privateKey: serverPrivate,
            publicKey: ephemeralPublic
        });

        return crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'sensor-server-v1', 32);
    }
};

export default ECCUtils;
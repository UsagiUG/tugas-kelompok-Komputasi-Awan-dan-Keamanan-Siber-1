import crypto from 'crypto'

const AESUtils = {
    decrypt: (aes_key, message) => {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            aes_key,
            Buffer.from(message.nonce, 'base64')
        );

        // const aad = JSON.stringify({
        //     sensor_id: message.sensor_id,
        //     transmission_timestamp: message.transmission_timestamp,
        //     encrypted_session_key: message.encrypted_session_key
        // });
        const aad = message.aad;
        const aadStr = JSON.stringify(aad, Object.keys(aad).sort());
        const aadBuffer = Buffer.from(aadStr, 'utf8');
        decipher.setAAD(aadBuffer);
        // console.log(aadBuffer);
        // console.log(Buffer.from(aad, 'utf8'));
        decipher.setAuthTag(Buffer.from(message.tag, 'base64'));

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(message.ciphertext, 'base64')),
            decipher.final()
        ]);

        return decrypted.toString('utf8');
    },

    decrypt2: (aes_key, message) => {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            aes_key,
            Buffer.from(message.nonce, 'base64')
        );

        // const aad = JSON.stringify({
        //     sensor_id: message.sensor_id,
        //     transmission_timestamp: message.transmission_timestamp,
        //     encrypted_session_key: message.encrypted_session_key
        // });
        const aad = message.aad;
        // const aadStr = JSON.stringify(aad, Object.keys(aad).sort());
        const aadBuffer = Buffer.from(aad, 'utf8');
        decipher.setAAD(aadBuffer);
        // console.log(aadBuffer);
        // console.log(Buffer.from(aad, 'utf8'));
        decipher.setAuthTag(Buffer.from(message.tag, 'base64'));

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(message.ciphertext, 'base64')),
            decipher.final()
        ]);

        return decrypted.toString('utf8');
    }
};

export default AESUtils;

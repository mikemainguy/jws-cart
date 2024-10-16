import * as jose from 'jose';
import {GenerateKeyPairResult, JWK, KeyLike} from 'jose';
import {v4 as uuidv4} from 'uuid';
import stringify from "fast-json-stable-stringify";
const iterations = 10000;
export type SignedObject = {
    signature: string,
    protected: string | undefined,
    payload: object,
}

export type KeyPair = {
    publicKey?: KeyLike,
    privateKey?: KeyLike,
    alg?: string
}

export type KeyStore = {
    set: (key: string, value: KeyPair) => void,
    get: (key: string) => KeyPair | undefined
}
export default class JsonSignature {
    private readonly _keys: KeyStore;

    constructor(keyStore?: KeyStore) {
        if (keyStore) {
            this._keys = keyStore
        } else {
            this._keys = new Map<string, KeyPair>();
        }
    }
    setPrivateKey(key: string, value: KeyLike) {
        this._keys.set(key, {privateKey: value});
    }
    setPublicKey(key: string, value: KeyLike) {
        this._keys.set(key, {publicKey: value});
    }
    public async getPublicKey(key: string): Promise<JWK> {
        const value = this._keys.get(key);
        if (!value?.publicKey) {
            throw new Error('Key not found');
        }
        return await jose.exportJWK(value.publicKey);
    }

    public async generateKeyPair(alg: string = 'PS256'): Promise<{ key: string, publicKey: JWK }> {
        const value: GenerateKeyPairResult = await jose.generateKeyPair(alg, {extractable: true});
        const key = uuidv4();
        this._keys.set(key, {publicKey: value.publicKey, privateKey: value.privateKey, alg: alg});
        const pubKey = await jose.exportJWK(value.publicKey);
        return {key, publicKey: pubKey};
    }

    public async sign(key: string, obj: object): Promise<SignedObject> {
        const value = this._keys.get(key);

        if (!value?.privateKey) {
            console.log( 'Key not found for ', key);
            throw new Error('Key not found');
        }
        let input = '';
        let jws = {signature: '', protected: '', payload: ''};
        const start = performance.now();
        console.log('start: ', start);
        for (let i = 0; i < iterations; i++) {
            input = stringify(obj);
            jws = await new jose.FlattenedSign(
                new TextEncoder().encode(input))
                .setProtectedHeader({alg: value?.alg, kid: key, b64: false, crit: ['b64']})
                .sign(value.privateKey);
        }
        console.log('Time taken: ', performance.now() - start);
        console.log('Time taken: ', (performance.now() - start)/iterations);

        return {
            signature: jws.signature,
            protected: jws.protected,
            payload: JSON.parse(input),
        }
    }
    public async verify(signed: SignedObject, key?: string): Promise<object> {
        let v = {};
        const start = performance.now();
        console.log('start: ', start);
        for (let i = 0; i < iterations; i++) {
            v = await this._verify(signed, key);
        }
        console.log('Time taken: ', performance.now() - start);
        console.log('Time taken: ', (performance.now() - start)/iterations);
        return v;

    }
    private async _verify(signed: SignedObject, key?: string): Promise<object> {
        let kid = key;
        try {
            const header = jose.decodeProtectedHeader({protected: signed.protected, signature: signed.signature});
            if (header.kid) {
                kid = header.kid;
            }

        } catch (e) {
            return {error: e.message};
        }
        if (!kid) {
            return {error: 'kid not found'};
        }
        const value = this._keys.get(kid);
        if (!value?.publicKey) {
            return {error: `Key ${kid} not found`};
        }
        const rsaPublicKey = value.publicKey;
        let options = {};
        if (value.alg) {
            options = {algorithms: [value.alg]}
        };
        try {
            const {
                payload
            } = await jose.flattenedVerify(
                { signature: signed.signature,
                    protected: signed.protected,
                    payload: stringify(signed.payload)}
                , rsaPublicKey, options);
            return JSON.parse(new TextDecoder().decode(payload));
        } catch (e) {
            return {error: e.message};
        }

    }
}
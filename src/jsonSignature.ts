import * as jose from 'jose';
import {GenerateKeyPairResult, JWK} from 'jose';
import {v4 as uuidv4} from 'uuid';

type KeySet = {
    key: GenerateKeyPairResult,
    alg: string
}
export type SignedObject = {
    signature: string,
    protected: string | undefined,
    payload: object,
    kid?: string,
    jwk?: JWK
}
export type KeyStore = {
    set: (key: string, value: KeySet) => void,
    get: (key: string) => KeySet | undefined
}
export default class JsonSignature {
    private readonly _keys: KeyStore;

    constructor(keyStore?: KeyStore) {
        if (keyStore) {
            this._keys = keyStore
        } else {
            this._keys = new Map<string, KeySet>();
        }
    }
    public async getPublicKey(key: string): Promise<JWK> {
        const value = this._keys.get(key);
        if (!value) {
            throw new Error('Key not found');
        }
        return await jose.exportJWK(value.key.publicKey);
    }

    public async generateKeyPair(alg: string = 'PS256'): Promise<{ key: string, publicKey: JWK }> {
        const value: GenerateKeyPairResult = await jose.generateKeyPair(alg, {extractable: false});
        const key = uuidv4();
        this._keys.set(key, {key: value, alg: alg});
        const pubKey = await jose.exportJWK(value.publicKey);
        return {key, publicKey: pubKey};
    }

    public async sign(key: string, obj: object): Promise<SignedObject> {
        const value = this._keys.get(key);
        if (!value) {
            throw new Error('Key not found');
        }
        const input = JSON.stringify(obj);

        const jws = await new jose.FlattenedSign(
            new TextEncoder().encode(input))
            .setProtectedHeader({alg: "PS256", kid: key, b64: false, crit: ['b64']})
            .sign(value.key.privateKey);
        return {
            signature: jws.signature,
            protected: jws.protected,
            payload: obj,
            kid: key,
            jwk: await jose.exportJWK(value.key.publicKey)
        }
    }

    public async verify(signed: SignedObject, key?: string): Promise<object> {
        let kid = key;
        try {
            const header = await jose.decodeProtectedHeader({protected: signed.protected, signature: signed.signature});
            if (header.kid) {
                kid = header.kid;
            }
            console.log(header);
        } catch (e) {
            return {error: e.message};
        }
        if (!kid) {
            return {error: 'kid not found'};
        }
        const value = this._keys.get(kid);
        if (!value?.key?.publicKey) {
            return {error: `Key ${kid} not found`};
        }
        const rsaPublicKey = value.key.publicKey;
        try {
            const {
                payload
            } = await jose.flattenedVerify(
                { signature: signed.signature,
                    protected: signed.protected,
                    payload: JSON.stringify(signed.payload)}
                , rsaPublicKey, {algorithms: ['PS256']});
            return JSON.parse(new TextDecoder().decode(payload));
        } catch (e) {
            return {error: e.message};
        }

    }
}
import "@mantine/core/styles.css";
import {Button, Group, Input, MantineProvider, Textarea} from "@mantine/core";
import {theme} from "./theme";
import {useState} from "react";
import * as jose from 'jose';
import {decode, encode} from "jose/base64url";


export default function App() {
    const [inputText, setInputText] = useState('');
    const [outputText, setOutputText] = useState('');
    const [verifiedText, setVerifiedText] = useState('');
    const [privateKey, setPrivateKey] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const sign = async() => {
        setOutputText('Working...');
        const text = JSON.stringify(JSON.parse(inputText));
        console.log(text);
        const rsaPrivateKey = await jose.importJWK(JSON.parse(privateKey), 'PS256');
        const jws = await new jose.FlattenedSign(
            new TextEncoder().encode(text))
            .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
            .sign(rsaPrivateKey);
        const output = {
            signature: encode(JSON.stringify(jws)),
            data: JSON.parse(text)
        }
        setOutputText(JSON.stringify(output));
    };
    const verify = async() => {
        try {
            const rsaPublicKey = await jose.importJWK(JSON.parse(publicKey), 'PS256');
            const input = JSON.parse(outputText);
            const signature = JSON.parse(new TextDecoder().decode(decode(input.signature)));
            const data = JSON.stringify(input.data);
            const source = {
                signature: signature.signature,
                protected: signature.protected,
                payload: data
            }
            input.payload = new TextEncoder().encode(data);
            const {payload, protectedHeader} = await jose.flattenedVerify(source, rsaPublicKey, {algorithms: ['PS256']});

            setVerifiedText(new TextDecoder().decode(payload));
        } catch (e) {
            setVerifiedText(e);
        }
    };
    const generate = async () => {
        const {privateKey: privKey, publicKey: pubKey}  = await jose.generateKeyPair('PS256', {extractable: true});
        const pub = await jose.exportJWK(pubKey);
        const priv = await jose.exportJWK(privKey);
        setPublicKey(JSON.stringify(pub,null,2));
        setPrivateKey(JSON.stringify(priv,null,2));
    }
    return <MantineProvider theme={theme}>
        <Button key="generate" onClick={generate}>Generate Key Pair</Button>
            <Input key="private" defaultValue={privateKey} label="Private Key" placeholder="Enter your private key"/>
            <Input key="public" defaultValue={publicKey} label="Public Key"
                   placeholder="Enter your private key"/>

        <Textarea label="Input" defaultValue={inputText} onChange={(e) => {setInputText(e.currentTarget.value)}} minRows={10} autosize={true} placeholder="Enter your message"/>
        <Textarea label="Output" defaultValue={outputText} onChange={(e) => {setOutputText(e.currentTarget.value)}} minRows={10} autosize={true}
                  placeholder="Enter your message"/>
        <Button onClick={sign}>Sign</Button>
        <Button onClick={verify}>Verify</Button>
        <Textarea label="Verified Output" defaultValue={verifiedText} minRows={10} autosize={true}
                  placeholder="Verification Result"/>
    </MantineProvider>;
}

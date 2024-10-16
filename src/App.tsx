import "@mantine/core/styles.css";
import {Button, Input, MantineProvider, Textarea, TextInput} from "@mantine/core";
import {theme} from "./theme";
import React, {useState} from "react";
import JsonSignature from "./jsonSignature.ts";

const composer = new JsonSignature();
let key: string = '';
composer.generateKeyPair().then((result) => {
    key = result.key;
});

export default function App() {
    const [inputText, setInputText] = useState('');
    const [outputText, setOutputText] = useState('');
    const [verifiedText, setVerifiedText] = useState('');
    const [publicKey, setPublicKey] = useState(key);

    const sign = async () => {
        try {
            const json = JSON.parse(inputText);
            const signed = await composer.sign(key, json);
            setOutputText(JSON.stringify(signed));
        } catch (e) {
            setOutputText(e.message);
        }
    }
    const verify = async () => {
        setVerifiedText('Working...');
        const input = JSON.parse(outputText);
        const verified = await composer.verify(input);
        setVerifiedText(JSON.stringify(verified));
    }

    const generate = async () => {
        setPublicKey(key);
    }
    return <MantineProvider theme={theme}>
        <Button key="generate" onClick={generate}>Generate Key Pair</Button>
        <TextInput key="public" defaultValue={publicKey} label="Public Key"
               placeholder="Enter your private key"/>

        <Textarea label="Input" defaultValue={inputText} onChange={(e) => {
            setInputText(e.currentTarget.value)
        }} minRows={5} autosize={true} placeholder="Enter your message"/>
        <Button onClick={sign}>Sign</Button>
        <Textarea label="Output" defaultValue={outputText} onChange={(e) => {
            setOutputText(e.currentTarget.value)
        }} minRows={5} autosize={true}
                  placeholder="Enter your message"/>

        <Button onClick={verify}>Verify</Button>
        <Textarea label="Verified Output" defaultValue={verifiedText} minRows={5} autosize={true}
                  placeholder="Verification Result"/>
    </MantineProvider>;
}

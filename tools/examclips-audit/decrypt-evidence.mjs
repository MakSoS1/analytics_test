import {readFile} from 'node:fs/promises';
import {openFile} from './crypto.mjs';
const [encryptedFile,metadataFile,privateKeyFile,outputZip]=process.argv.slice(2);
if(!encryptedFile||!metadataFile||!privateKeyFile||!outputZip)throw Error('Usage: node decrypt-evidence.mjs EVIDENCE_ENC METADATA_JSON PRIVATE_KEY_PEM OUTPUT_ZIP');
const metadata=JSON.parse(await readFile(metadataFile,'utf8'));
if(metadata.context?.purpose!=='evidence')throw Error('This is not an evidence archive');
await openFile(encryptedFile,outputZip,metadata,await readFile(privateKeyFile,'utf8'),metadata.context);
console.log('Evidence archive decrypted and authentication tag verified');

import test from 'node:test';import assert from 'node:assert/strict';
import {validatePngRequest} from '../local-ocr-bridge.js';
const valid=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),Buffer.alloc(128,7)]).toString('base64');
test('same-machine OCR bridge accepts only small explicit PNG payloads',()=>{
 assert.equal(validatePngRequest({language:'ru',png_base64:valid}).language,'ru');
 assert.throws(()=>validatePngRequest({language:'fr',png_base64:valid}));
 assert.throws(()=>validatePngRequest({language:'en',png_base64:Buffer.from('wrong').toString('base64')}));
 assert.throws(()=>validatePngRequest({language:'en',png_base64:'!!notbase64'}));
 assert.throws(()=>validatePngRequest({language:'en',png_base64:'A'.repeat(4800000)}));
});

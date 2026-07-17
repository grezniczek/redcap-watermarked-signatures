'use strict';

const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const children = [];
const form = {
    querySelector(selector) {
        assert.strictEqual(selector, 'input[name="sigwm_envelope"]');
        return children.find((child) => child.name === 'sigwm_envelope') || null;
    },
    appendChild(child) {
        child.parent = this;
        children.push(child);
    }
};

const document = {
    getElementById(id) {
        return id === 'form_file_upload' ? form : null;
    },
    createElement(tagName) {
        return {
            tagName,
            remove() {
                const index = children.indexOf(this);
                if (index !== -1) {
                    children.splice(index, 1);
                }
            }
        };
    }
};

const calls = [];
const window = {
    document,
    jQuery: {},
    console: { debug() {} },
    REDCapSignatureWatermark: {
        envelopes: {
            participant_signature: 'envelope-a',
            witness_signature: 'envelope-b'
        },
        debug: false
    },
    filePopUp() {
        calls.push(Array.from(arguments));
        return 'original-result';
    }
};

const context = vm.createContext({ window, document });
const source = fs.readFileSync(path.join(__dirname, '..', 'js', 'signature-watermark.js'), 'utf8');
vm.runInContext(source, context);

const result = window.filePopUp('participant_signature', 1, 0);
assert.strictEqual(result, 'original-result', 'Wrapped filePopUp changed the return value.');
assert.strictEqual(form.querySelector('input[name="sigwm_envelope"]').value, 'envelope-a', 'Field A received the wrong envelope.');

window.filePopUp('witness_signature', 2, 0);
assert.strictEqual(children.length, 1, 'Opening a second field duplicated the envelope input.');
assert.strictEqual(form.querySelector('input[name="sigwm_envelope"]').value, 'envelope-b', 'Field B received a stale envelope.');

window.filePopUp('ordinary_upload', 0, 1);
assert.strictEqual(form.querySelector('input[name="sigwm_envelope"]'), null, 'A non-signature upload retained a stale envelope.');

window.filePopUp('participant_signature', 0, 0);
assert.strictEqual(form.querySelector('input[name="sigwm_envelope"]'), null, 'Signature-disabled routing attached an envelope.');
assert.deepStrictEqual(calls[1], ['witness_signature', 2, 0], 'Original filePopUp arguments were changed.');

const installedWrapper = window.filePopUp;
vm.runInContext(source, context);
assert.strictEqual(window.filePopUp, installedWrapper, 'Script installation was not idempotent.');

console.log('Watermarked Signatures JavaScript smoke tests passed.');

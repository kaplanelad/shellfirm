
let imports = {};
imports['__wbindgen_placeholder__'] = module.exports;
let wasm;
const { TextDecoder, TextEncoder } = require(`util`);

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

let cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_3.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
/**
 * Validates a command with the provided options.
 *
 * Converts `WasmValidationOptions` into core options and returns a
 * `WasmValidationResult` suitable for JavaScript.
 * @param {string} command
 * @param {WasmValidationOptions} options
 * @returns {WasmValidationResult}
 */
module.exports.validate_command_wasm = function(command, options) {
    const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(options, WasmValidationOptions);
    var ptr1 = options.__destroy_into_raw();
    const ret = wasm.validate_command_wasm(ptr0, len0, ptr1);
    return WasmValidationResult.__wrap(ret);
};

/**
 * Validates a command without options (backward compatibility).
 *
 * Uses the default validation configuration.
 * @param {string} command
 * @returns {WasmValidationResult}
 */
module.exports.validate_command_simple_wasm = function(command) {
    const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validate_command_simple_wasm(ptr0, len0);
    return WasmValidationResult.__wrap(ret);
};

/**
 * Validates a command by parsing, splitting, and checking each part.
 *
 * Handles complex shell commands with operators like `&`, `|`, `&&`, and `||`.
 * @param {string} command
 * @returns {WasmValidationResult}
 */
module.exports.validate_command_with_split_wasm = function(command) {
    const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validate_command_with_split_wasm(ptr0, len0);
    return WasmValidationResult.__wrap(ret);
};

/**
 * Validates a command with options using the split logic.
 *
 * Similar to [`validate_command_with_split_wasm`] but allows specifying deny
 * patterns and severities via `WasmValidationOptions`.
 * @param {string} command
 * @param {WasmValidationOptions} options
 * @returns {WasmValidationResult}
 */
module.exports.validate_command_with_options_wasm = function(command, options) {
    const ptr0 = passStringToWasm0(command, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    _assertClass(options, WasmValidationOptions);
    var ptr1 = options.__destroy_into_raw();
    const ret = wasm.validate_command_with_options_wasm(ptr0, len0, ptr1);
    return WasmValidationResult.__wrap(ret);
};

/**
 * Returns all available patterns as a JSON string.
 *
 * The JSON is an array of pattern objects as defined by the core checks.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 * @returns {string}
 */
module.exports.get_all_patterns_wasm = function() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.get_all_patterns_wasm();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
};

/**
 * Returns the list of pattern categories (groups).
 *
 * Groups correspond to the `from` field in each pattern.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 * @returns {string}
 */
module.exports.get_pattern_groups_wasm = function() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.get_pattern_groups_wasm();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
};

/**
 * Returns the patterns for a specific group as a JSON string.
 *
 * The `group` value corresponds to the `from` field on each pattern.
 *
 * # Errors
 *
 * Returns an error if pattern loading fails or if serialization to JSON fails.
 * @param {string} group
 * @returns {string}
 */
module.exports.get_patterns_for_group_wasm = function(group) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(group, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.get_patterns_for_group_wasm(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
};

/**
 * Initializes the WASM module.
 *
 * Sets up panic hooks (when enabled) and performs allocator configuration.
 */
module.exports.init = function() {
    wasm.init();
};

/**
 * Creates a simple file-existence cache for testing.
 *
 * Returns a JSON object mapping example file paths to boolean existence.
 * @returns {string}
 */
module.exports.create_test_file_cache = function() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.create_test_file_cache();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
};

/**
 * Returns a string confirming that the WASM module is working.
 * @returns {string}
 */
module.exports.test_wasm_module = function() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.test_wasm_module();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
};

const WasmValidationOptionsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmvalidationoptions_free(ptr >>> 0, 1));
/**
 * WASM-compatible validation options.
 *
 * Holds configuration passed from JavaScript to influence validation behavior.
 */
class WasmValidationOptions {

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmValidationOptionsFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmvalidationoptions_free(ptr, 0);
    }
    /**
     * Creates new validation options with empty settings.
     */
    constructor() {
        const ret = wasm.wasmvalidationoptions_new();
        this.__wbg_ptr = ret >>> 0;
        WasmValidationOptionsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Sets deny pattern IDs from a JSON array of strings.
     *
     * The input must be a JSON array, for example: `"[\"group:id\", \"group:id2\"]"`.
     * Passing an empty string clears the list.
     *
     * # Errors
     *
     * Returns an error if the provided value is not valid JSON or cannot be
     * deserialized into `Vec<String>`.
     * @param {string} json_array
     */
    set_deny_pattern_ids(json_array) {
        const ptr0 = passStringToWasm0(json_array, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvalidationoptions_set_deny_pattern_ids(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Sets allowed severities from a JSON array of strings.
     *
     * The input must be a JSON array, for example: `"[\"low\", \"medium\"]"`.
     * Passing an empty string clears the list.
     *
     * # Errors
     *
     * Returns an error if the provided value is not valid JSON or cannot be
     * deserialized into `Vec<String>`.
     * @param {string} json_array
     */
    set_allowed_severities(json_array) {
        const ptr0 = passStringToWasm0(json_array, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmvalidationoptions_set_allowed_severities(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
module.exports.WasmValidationOptions = WasmValidationOptions;

const WasmValidationResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmvalidationresult_free(ptr >>> 0, 1));
/**
 * WASM-compatible validation result.
 *
 * Wraps the core validation outcome in a JS-friendly form. Matched checks are
 * serialized into a JSON string to avoid exposing Rust types across the WASM boundary.
 */
class WasmValidationResult {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmValidationResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmValidationResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmValidationResultFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmvalidationresult_free(ptr, 0);
    }
    /**
     * Returns the matched checks as a JSON string.
     *
     * The JSON is an array of matched check objects. If no checks matched,
     * the string will be `"[]"`.
     * @returns {string}
     */
    get matches() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmvalidationresult_matches(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Indicates whether a challenge should be presented to the user.
     * @returns {boolean}
     */
    get should_challenge() {
        const ret = wasm.wasmvalidationresult_should_challenge(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Indicates whether the command should be denied.
     * @returns {boolean}
     */
    get should_deny() {
        const ret = wasm.wasmvalidationresult_should_deny(this.__wbg_ptr);
        return ret !== 0;
    }
}
module.exports.WasmValidationResult = WasmValidationResult;

module.exports.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
    let deferred0_0;
    let deferred0_1;
    try {
        deferred0_0 = arg0;
        deferred0_1 = arg1;
        console.error(getStringFromWasm0(arg0, arg1));
    } finally {
        wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
    }
};

module.exports.__wbg_new_8a6f238a6ece86ea = function() {
    const ret = new Error();
    return ret;
};

module.exports.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
    const ret = arg1.stack;
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
};

module.exports.__wbindgen_init_externref_table = function() {
    const table = wasm.__wbindgen_export_3;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
    ;
};

module.exports.__wbindgen_string_new = function(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

module.exports.__wbindgen_throw = function(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

const path = require('path').join(__dirname, 'shellfirm_core_bg.wasm');
const bytes = require('fs').readFileSync(path);

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
wasm = wasmInstance.exports;
module.exports.__wasm = wasm;

wasm.__wbindgen_start();


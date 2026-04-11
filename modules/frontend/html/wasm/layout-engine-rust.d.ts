declare namespace wasm_bindgen {
    /* tslint:disable */
    /* eslint-disable */

    export function adalancheLayoutAnimationStart(request_json: string): string;

    export function adalancheLayoutAnimationStep(request_json: string): string;

    export function adalancheLayoutAnimationStop(request_json: string): string;

    export function adalancheLayoutDescribe(): string;

    export function adalancheLayoutRun(request_json: string): string;

}
declare type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

declare interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly adalancheLayoutAnimationStart: (a: number, b: number) => [number, number];
    readonly adalancheLayoutAnimationStep: (a: number, b: number) => [number, number];
    readonly adalancheLayoutAnimationStop: (a: number, b: number) => [number, number];
    readonly adalancheLayoutDescribe: () => [number, number];
    readonly adalancheLayoutRun: (a: number, b: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
declare function wasm_bindgen (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

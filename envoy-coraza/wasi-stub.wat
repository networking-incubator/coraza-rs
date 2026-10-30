;; ENOSYS stubs for the five wasi_snapshot_preview1 imports of the
;; envoy-coraza filter. Envoy's Proxy-Wasm host below 1.40 (e.g. Istio 1.30,
;; Envoy 1.38.x) does not provide them and refuses to load the module; the
;; stubs only satisfy the loader, the filter's validated configuration never
;; reaches filesystem-backed features. The release workflow links them into
;; the published artifacts with wasm-merge; on Envoy 1.40+ the extra imports
;; are simply unused. errno 52 is __WASI_ERRNO_NOSYS.
(module
  (func (export "fd_filestat_get") (param i32 i32) (result i32) (i32.const 52))
  (func (export "fd_readdir") (param i32 i32 i32 i64 i32) (result i32) (i32.const 52))
  (func (export "path_create_directory") (param i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_filestat_get") (param i32 i32 i32 i32 i32) (result i32) (i32.const 52))
  (func (export "path_unlink_file") (param i32 i32 i32) (result i32) (i32.const 52))
)

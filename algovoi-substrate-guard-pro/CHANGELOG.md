# Changelog

## 0.1.1 — 2026-07-26

- `REJECT_NON_STRING_KEY` is now raised for non-string object keys; previously these incorrectly returned `REJECT_INVALID_UTF8`.
- `REJECT_UNSUPPORTED_TYPE` is now raised for values that are not JSON types (set, tuple, bytes, etc.); previously these incorrectly returned `REJECT_UNSAFE_NUMBER`.
- Consumers switching on `reject_code` must handle the new values. Archived signed decisions retain the old codes for those input classes and will not match a re-run.

## 0.1.0

Initial release.

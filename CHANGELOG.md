# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Stop accumulating bodyless requests in `pending_requests` when body inspection is enabled: known-empty bodies (`Content-Length: 0` for every value) finish ModSecurity phase 2 on `request_headers` and are not parked.
- Clear pending body buffers on `response_headers` and when requests complete or drain, with a time-based sweep and a hard cap on concurrent parked requests (new parks at the cap are rejected).
- Fail closed when body inspection is enabled and a body chunk arrives with no matching pending request (deny instead of allow); oversize bodies and chunks when inspection is off still allow.
- Expose `modsec_pending_requests` in the agent metrics report.
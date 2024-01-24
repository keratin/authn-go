# Changelog

Based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## HEAD

* Replace deprecated gopkg.in/square/go-jose.v2 with github.com/square/go-jose/v3 [#29]
* Update golang.org/x/crypto from 0.14.0 to 0.17.0 [#27]

## 1.2.0

* Add `authn.ClaimsFrom` and `authn.ClaimsFromWithAudience` to support
  extraction of identity token claims.

## 1.1.0

### Added

* `authn.SubjectFromWithAudience` adds support for multi-domain authentication [#15]

## 1.0.0

### Added

* All admin API actions: GetAccount, Update, LockAccount, UnlockAccount, ArchiveAccount, ImportAccount, ExpirePassword, ServiceStats, ServerStats [#10]

## 0.2.0

### Changed

* Export more funcs and types to improve library flexibility [#9]

## 0.1.0

### Added

* Provide AuthN ID token verifier for minimum integration [#1]

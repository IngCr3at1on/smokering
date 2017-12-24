### Smoke Ring

[![GoDoc][docs_badge]][docs]
[![Build Status][travis_badge]][travis]

---

A minimal in-memory encrypted keyring using only standard libs.

Smoke Ring is encryption agnostic, it is designed to be used as a package by another application where the application provides the block cipher for encrypting the keys. This means the application only has to keep track of the master key for this cipher while all their keys are safely stored in Smoke Ring.

[docs]: https://godoc.org/github.com/IngCr3at1on/smokering
[docs_badge]: https://godoc.org/github.com/IngCr3at1on/smokering?status.svg
[travis]: https://travis-ci.org/IngCr3at1on/smokering
[travis_badge]: https://travis-ci.org/IngCr3at1on/smokering.svg?branch=master
### Smoke Ring

A minimal in-memory encrypted keyring using only standard libs.

Smoke Ring is encryption agnostic, it is designed to be used as a package by another application where the application provides the block cipher for encrypting the keys. This means the application only has to keep track of the master key for this cipher while all their keys are safely stored in Smoke Ring.

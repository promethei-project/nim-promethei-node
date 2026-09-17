## Copyright (c) 2025 Promethei Authors
## Copyright (c) 2022 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.

{.push raises: [].}

import pkg/questionable/results
import pkg/libp2p/crypto/crypto
import pkg/libp2p/crypto/rng as libp2p_rng

import ./fileutils
import ../errors
import ../logutils
import ../rng

export crypto

type
  PrometheiKeyError = object of PrometheiError
  PrometheiKeyUnsafeError = object of PrometheiKeyError

proc setupKey*(path: string): ?!PrivateKey =
  if not path.fileAccessible({AccessFlags.Find}):
    info "Creating a private key and saving it"
    let
      res =
        ?PrivateKey.random(libp2p_rng.newBearSslRng(Rng.instance())).mapFailure(
          PrometheiKeyError
        )
      bytes = ?res.getBytes().mapFailure(PrometheiKeyError)

    ?path.secureWriteFile(bytes).mapFailure(PrometheiKeyError)
    return PrivateKey.init(bytes).mapFailure(PrometheiKeyError)

  info "Found a network private key"
  if not ?checkSecureFile(path).mapFailure(PrometheiKeyError):
    warn "The network private key file is not safe, aborting"
    return failure newException(
      PrometheiKeyUnsafeError, "The network private key file is not safe"
    )

  let kb = ?path.readAllBytes().mapFailure(PrometheiKeyError)
  return PrivateKey.init(kb).mapFailure(PrometheiKeyError)

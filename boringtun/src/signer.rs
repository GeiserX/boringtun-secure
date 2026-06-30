// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! signer — sign-on-behalf transport (boringtun-secure, L3): keep the WireGuard static private key out
//! of the datapath **process** entirely.
//!
//! A small signer process holds the key (in guarded secure memory, via
//! [`crate::noise::handshake::default_agent`]) and performs the handshake's only static-key operation —
//! `DH(static_private, peer_public)` — on request, over a unix socket. The datapath uses [`SignerClient`]
//! (a [`crate::noise::handshake::StaticKeyAgent`]) which holds ONLY the socket and the (public) static
//! public key. So a compromise of the datapath process never yields the private key — it lives in a
//! different process.
//!
//! Wire protocol (fixed-size, one request/response per DH): the client writes 32 bytes (the peer public
//! key); the signer replies with 32 bytes (the DH shared secret). The static PUBLIC key is never sent —
//! it is public, and the client is constructed with it.
//!
//! Deployment: run [`serve_stream`] in the signer process (authorize the caller with [`peer_uid`]
//! first); build the datapath's `Tunn` with
//! `Tunn::new_with_agent(Box::new(SignerClient::new(stream, static_public)), …)`.

use crate::noise::handshake::StaticKeyAgent;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

/// A [`StaticKeyAgent`] that performs each static-key DH by asking a signer process over a unix socket.
/// Holds only the socket and the (public) static public key — never the private key.
pub struct SignerClient {
    stream: Mutex<UnixStream>,
    static_public: [u8; 32],
}

impl SignerClient {
    /// Wrap a stream connected to a signer, with the (public) static public key the signer holds.
    pub fn new(stream: UnixStream, static_public: [u8; 32]) -> Self {
        SignerClient {
            stream: Mutex::new(stream),
            static_public,
        }
    }
}

impl StaticKeyAgent for SignerClient {
    fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let Ok(mut stream) = self.stream.lock() else {
            return [0u8; 32];
        };
        // Fail closed: a broken signer link yields a zero "shared secret", which fails the handshake (a
        // wrong DH → AEAD tag mismatch) rather than ever producing a usable session.
        let mut out = [0u8; 32];
        if stream.write_all(peer_public).is_ok() && stream.read_exact(&mut out).is_ok() {
            out
        } else {
            [0u8; 32]
        }
    }

    fn public_key(&self) -> [u8; 32] {
        self.static_public
    }
}

/// Serve DH requests on one connected stream using `key_agent` (which holds the static key — e.g. the
/// [`crate::noise::handshake::default_agent`], keeping it in guarded secure memory). Each request: read
/// 32 bytes (peer public key), reply with 32 bytes (`DH(static_private, peer_public)`). Returns when the
/// peer disconnects.
pub fn serve_stream(mut stream: UnixStream, key_agent: &dyn StaticKeyAgent) -> std::io::Result<()> {
    let mut peer = [0u8; 32];
    loop {
        match stream.read_exact(&mut peer) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let shared = key_agent.diffie_hellman(&peer);
        stream.write_all(&shared)?;
    }
}

/// The uid of the process connected on `stream` (Linux `SO_PEERCRED`) — the signer authorizes the
/// caller (the datapath must run as a known, separate uid) before serving DHs.
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED on a connected AF_UNIX stream fills `ucred`; `len` matches its size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ucred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::{Tunn, TunnResult};
    use crate::x25519;
    use rand_core::OsRng;

    fn write_to_network(r: TunnResult<'_>) -> Vec<u8> {
        match r {
            TunnResult::WriteToNetwork(b) => b.to_vec(),
            _ => panic!("expected a WriteToNetwork handshake message"),
        }
    }

    /// A real WireGuard handshake completes with the responder's static key held ONLY by a signer
    /// reachable over a unix socket — the datapath `Tunn` never receives the key (it holds a
    /// `SignerClient` = a socket + the public key). In production the signer is a separate process; here
    /// a thread drives the identical socket protocol.
    #[test]
    fn a_handshake_completes_with_the_static_key_held_only_by_a_signer() {
        let (sign_side, data_side) = UnixStream::pair().unwrap();

        let responder_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = x25519::PublicKey::from(&responder_secret).to_bytes();

        // The signer holds the responder's key in guarded memory (the default agent).
        let key_agent = crate::noise::handshake::default_agent(responder_secret);
        let signer = std::thread::spawn(move || {
            let _ = serve_stream(sign_side, key_agent.as_ref());
        });

        let initiator_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let initiator_public = x25519::PublicKey::from(&initiator_secret);

        // The datapath responder holds ONLY the socket — no key.
        let client = SignerClient::new(data_side, responder_public);
        let mut responder =
            Tunn::new_with_agent(Box::new(client), initiator_public, None, None, 2, None);
        let mut initiator = Tunn::new(
            initiator_secret,
            x25519::PublicKey::from(responder_public),
            None,
            None,
            1,
            None,
        );

        // Drive the handshake. The responder's static-key DH crosses the socket to the signer.
        let mut buf = [0u8; 2048];
        let init = write_to_network(initiator.format_handshake_initiation(&mut buf, false));
        let mut buf2 = [0u8; 2048];
        let resp = write_to_network(responder.decapsulate(None, &init, &mut buf2));
        let mut buf3 = [0u8; 2048];
        // The initiator completing (a WriteToNetwork keepalive) proves the signer-served DH produced the
        // correct shared secret — i.e. the key-less datapath handshakes correctly.
        let _ = write_to_network(initiator.decapsulate(None, &resp, &mut buf3));

        drop(responder); // closes data_side → the signer's serve loop returns
        signer.join().unwrap();
    }
}

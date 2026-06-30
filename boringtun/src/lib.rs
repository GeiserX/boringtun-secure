// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

pub(crate) mod serialization;

/// Secure storage for the static private key (boringtun-secure key-residency hardening).
pub(crate) mod secure_mem;

/// Sign-on-behalf transport (L3): a signer process performs the static-key DH so the datapath process
/// never holds the key. Unix-only (uses `AF_UNIX` sockets).
#[cfg(unix)]
pub mod signer;

/// The static-key Diffie-Hellman seam (L3): inject a [`StaticKeyAgent`] via
/// [`noise::Tunn::new_with_agent`] (or use [`default_agent`] to hold the key in guarded memory).
pub use noise::handshake::{default_agent, StaticKeyAgent};

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}

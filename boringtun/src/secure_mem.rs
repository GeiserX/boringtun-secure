//! Secure storage for a small long-lived secret (the WireGuard static private key).
//!
//! The key's 32 bytes are held in the most protected memory the platform offers, and are made
//! readable ONLY for the brief window of a Diffie-Hellman during a handshake — the rest of the time
//! the page is `PROT_NONE` (no access). This is the libsodium guarded-memory model.
//!
//! Platform backing (best first):
//! * **Linux** — `memfd_secret(2)` (kernel 5.14+): memory mapped only in *this* process's page
//!   tables and **removed from the kernel direct map**, so it is invisible to the kernel, to other
//!   processes, to DMA, to coredumps and to swap. If `memfd_secret` is unavailable (old kernel,
//!   `secretmem.enable=0`, seccomp), we **fail closed to an anonymous `mmap` + `mlock`** — never break
//!   the datapath.
//! * **Other Unix (macOS/iOS)** — anonymous `mmap` + `mlock` (no swap) + `mprotect` guarding.
//! * **Windows** — a plain heap box (compile-only fallback; this crate's primary targets are the
//!   Linux datapath and the macOS network extension). The bytes are still zeroized on drop.
//!
//! Honest ceiling: while a DH runs, the 32 bytes are briefly copied into a normal stack
//! `StaticSecret` (the dalek API needs the typed value) and zeroized immediately after — so the raw
//! key is in ordinary memory only for ~microseconds per handshake. No userspace scheme can defeat a
//! physical DRAM cold-boot or a debugger attached to *this* process; those need hardware memory
//! encryption or a secure element that does X25519 (which does not exist for Curve25519).

// Only the non-Unix (Windows) fallback zeroizes via the trait; the Unix paths wipe with write_bytes.
#[cfg(not(unix))]
use zeroize::Zeroize;

/// The number of secret bytes stored (an x25519 scalar).
pub const SECRET_LEN: usize = 32;

/// A 32-byte secret held in platform-secure memory, accessible only through [`SecretStore::with_bytes`].
pub struct SecretStore {
    inner: Inner,
}

impl SecretStore {
    /// Move `bytes` into secure memory. The caller's copy should be zeroized afterwards.
    pub fn new(bytes: &[u8; SECRET_LEN]) -> Self {
        SecretStore {
            inner: Inner::new(bytes),
        }
    }

    /// Briefly make the secret readable, run `f` with it, then make it inaccessible again.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8; SECRET_LEN]) -> R) -> R {
        self.inner.with_bytes(f)
    }
}

// ---------------------------------------------------------------------------------------------
// Unix (Linux + macOS/iOS): a page-aligned mapping, mlock'd, mprotect(PROT_NONE) at rest.
// ---------------------------------------------------------------------------------------------
#[cfg(unix)]
struct Inner {
    ptr: *mut libc::c_void,
    page: usize,
    /// `Some(fd)` when backed by `memfd_secret` (Linux); `None` for an anonymous mapping.
    memfd: Option<libc::c_int>,
}

// The pointer is owned by this struct and only dereferenced under the mprotect dance; it is safe to
// move the struct across threads (the mapping address is stable).
#[cfg(unix)]
unsafe impl Send for Inner {}
#[cfg(unix)]
unsafe impl Sync for Inner {}

#[cfg(unix)]
impl Inner {
    fn page_size() -> usize {
        // SAFETY: sysconf is always callable; a non-positive result falls back to 4 KiB.
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p > 0 {
            p as usize
        } else {
            4096
        }
    }

    fn new(bytes: &[u8; SECRET_LEN]) -> Self {
        let page = Self::page_size();

        // 1. Allocate a single page. Prefer Linux memfd_secret; fall back to an anonymous mapping.
        let (ptr, memfd) = Self::map_secret(page);

        // 2. Copy the secret in (the mapping is read/write at this point), then mlock + lock it down.
        // SAFETY: ptr is a valid, writable mapping of at least `page` (>= SECRET_LEN) bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, SECRET_LEN);
            // Best-effort: never let a lock failure (RLIMIT_MEMLOCK) break the datapath.
            let _ = libc::mlock(ptr, page);
            // No access until a DH explicitly opens a read window.
            let _ = libc::mprotect(ptr, page, libc::PROT_NONE);
        }
        Inner { ptr, page, memfd }
    }

    /// Map one page of secret memory. Linux: `memfd_secret` → `mmap`; on any failure, or on other
    /// Unix, an anonymous private mapping. Returns the mapping pointer and the optional memfd.
    fn map_secret(page: usize) -> (*mut libc::c_void, Option<libc::c_int>) {
        #[cfg(target_os = "linux")]
        {
            // memfd_secret(2) — kernel 5.14+. Use the raw syscall so an old libc without the wrapper
            // still builds; SYS_memfd_secret is provided by libc on supported arches.
            // SAFETY: a syscall with a constant flag argument.
            let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, 0 as libc::c_uint) };
            if fd >= 0 {
                let fd = fd as libc::c_int;
                // SAFETY: fd is a fresh secretmem fd; ftruncate sizes it to one page.
                let sized = unsafe { libc::ftruncate(fd, page as libc::off_t) };
                if sized == 0 {
                    // SAFETY: mapping a freshly-sized secretmem fd, one page, RW.
                    let p = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            page,
                            libc::PROT_READ | libc::PROT_WRITE,
                            libc::MAP_SHARED,
                            fd,
                            0,
                        )
                    };
                    if p != libc::MAP_FAILED {
                        return (p, Some(fd));
                    }
                }
                // memfd path failed after opening the fd — close it and fall through to anon.
                // SAFETY: fd is open and ours.
                unsafe { libc::close(fd) };
            }
            // else: ENOSYS / secretmem.enable=0 / seccomp → fail closed to an anonymous mapping.
        }
        Self::map_anon(page)
    }

    /// Anonymous private page (the cross-Unix fallback).
    fn map_anon(page: usize) -> (*mut libc::c_void, Option<libc::c_int>) {
        // SAFETY: a standard anonymous private mmap of one page.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(p != libc::MAP_FAILED, "secure_mem: mmap of one page failed");
        (p, None)
    }

    fn with_bytes<R>(&self, f: impl FnOnce(&[u8; SECRET_LEN]) -> R) -> R {
        // Open a read window, run f, then close it again — even if f panics (the guard's Drop runs).
        struct ReadWindow<'a>(&'a Inner);
        impl Drop for ReadWindow<'_> {
            fn drop(&mut self) {
                // SAFETY: re-protecting our own mapping.
                unsafe { libc::mprotect(self.0.ptr, self.0.page, libc::PROT_NONE) };
            }
        }
        // SAFETY: making our own mapping readable for the duration of f.
        unsafe { libc::mprotect(self.ptr, self.page, libc::PROT_READ) };
        let _w = ReadWindow(self);
        // SAFETY: ptr points to at least SECRET_LEN readable bytes for the window's lifetime.
        let arr: &[u8; SECRET_LEN] = unsafe { &*(self.ptr as *const [u8; SECRET_LEN]) };
        f(arr)
    }
}

#[cfg(unix)]
impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: restore write access, wipe the secret, unlock, unmap, and (Linux) close the memfd.
        unsafe {
            libc::mprotect(self.ptr, self.page, libc::PROT_READ | libc::PROT_WRITE);
            std::ptr::write_bytes(self.ptr as *mut u8, 0, SECRET_LEN);
            libc::munlock(self.ptr, self.page);
            libc::munmap(self.ptr, self.page);
            if let Some(fd) = self.memfd {
                libc::close(fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Non-Unix (Windows): compile-only fallback — a heap box, zeroized on drop (no page protection).
// ---------------------------------------------------------------------------------------------
#[cfg(not(unix))]
struct Inner {
    bytes: Box<[u8; SECRET_LEN]>,
}

#[cfg(not(unix))]
impl Inner {
    fn new(bytes: &[u8; SECRET_LEN]) -> Self {
        Inner {
            bytes: Box::new(*bytes),
        }
    }
    fn with_bytes<R>(&self, f: impl FnOnce(&[u8; SECRET_LEN]) -> R) -> R {
        f(&self.bytes)
    }
}

#[cfg(not(unix))]
impl Drop for Inner {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_secret_through_secure_memory() {
        let secret = [7u8; SECRET_LEN];
        let store = SecretStore::new(&secret);
        // The stored bytes read back identically through the guarded read window.
        store.with_bytes(|b| assert_eq!(b, &secret));
        // And again — the window can be opened repeatedly.
        store.with_bytes(|b| assert_eq!(b, &secret));
    }

    #[test]
    fn distinct_secrets_are_independent() {
        let a = SecretStore::new(&[1u8; SECRET_LEN]);
        let b = SecretStore::new(&[2u8; SECRET_LEN]);
        a.with_bytes(|x| assert_eq!(x[0], 1));
        b.with_bytes(|x| assert_eq!(x[0], 2));
    }
}

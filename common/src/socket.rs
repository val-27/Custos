//! AF_XDP UMEM and socket configuration helpers.
//!
//! # Purpose
//! Centralizes the UMEM construction, socket bind configuration, and Fill Queue
//! population that was previously copy-pasted verbatim across every Custos
//! processing phase (1–4). Each phase had ~70 lines of identical startup code;
//! this module reduces each call site to ~25 lines.
//!
//! # Safety Invariants
//! [`populate_fill_queue`] is `unsafe` because it requires all provided frame
//! descriptors to be owned and not in flight. This precondition must be upheld
//! by the caller (trivially true immediately after [`build_umem`]).
//!
//! # Performance Rationale
//! All helpers operate at startup, outside the packet loop. They exist to reduce
//! boilerplate risk (e.g. missing `// SAFETY:` comments, inconsistent constants,
//! diverging ring sizes) rather than to optimize per-call cost.

use std::num::NonZeroU32;

use xsk_rs::{
    config::{BindFlags, LibxdpFlags, SocketConfig, UmemConfigBuilder},
    FillQueue, FrameDesc, Umem,
};

use crate::UMEM_FRAME_SIZE;

/// Constructs a Custos-standard UMEM memory pool with pre-allocated frame descriptors.
///
/// # Purpose
/// Builds a [`Umem`] with the standard Custos 2 KiB frame layout and zero headroom,
/// returning one [`FrameDesc`] per allocated frame. These descriptors are later
/// submitted to the Fill Queue via [`populate_fill_queue`].
///
/// # Arguments
/// - `frame_count` — total number of UMEM frames to allocate. Must be a power of two.
/// - `ring_size` — fill and completion ring capacity. Use [`crate::UMEM_RING_SIZE`]
///   (2048) for phases 1–3, or `frame_count` for phase 4 multi-queue where each
///   per-queue UMEM owns its full ring.
/// - `huge_pages` — if `true`, requests 2 MiB hugepage-backed allocation for lower
///   TLB pressure. Requires pre-allocated hugepages on the host.
///
/// # Errors
/// Returns the underlying `xsk_rs` error if `UmemConfig::build()` or `Umem::new()` fails.
///
/// # Performance Rationale
/// Called once at startup. All frames are pre-allocated here; the packet processing
/// hot path performs zero heap allocation.
pub fn build_umem(
    frame_count: NonZeroU32,
    ring_size: NonZeroU32,
    huge_pages: bool,
) -> Result<(Umem, Vec<FrameDesc>), Box<dyn std::error::Error>> {
    // UMEM_FRAME_SIZE = 2048, guaranteed non-zero by its definition.
    let frame_size_nz =
        NonZeroU32::new(UMEM_FRAME_SIZE).expect("UMEM_FRAME_SIZE must be non-zero");

    let umem_config = UmemConfigBuilder::new()
        .frame_size(frame_size_nz)
        .frame_headroom(0)
        .fill_queue_size(ring_size)
        .comp_queue_size(ring_size)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build UmemConfig: {:?}", e);
            e
        })?;

    let (umem, frame_descs) = Umem::new(umem_config, frame_count, huge_pages)
        .map_err(|e| {
            tracing::error!("Failed to initialize UMEM: {:?}", e);
            e
        })?;

    tracing::info!(
        "Initialized UMEM: {} frames \u{00d7} {} B = {} KiB",
        frame_count.get(),
        UMEM_FRAME_SIZE,
        (frame_count.get() as usize * UMEM_FRAME_SIZE as usize) / 1024,
    );

    Ok((umem, frame_descs))
}

/// Builds an AF_XDP [`SocketConfig`] with the specified bind-mode flags.
///
/// # Purpose
/// Consolidates the bind-flag selection logic (`XDP_COPY` / `XDP_ZEROCOPY` /
/// `INHIBIT_PROG_LOAD`) that was previously duplicated across all processing phases.
///
/// # Arguments
/// - `force_copy` — forces copy-mode (`XDP_COPY`). Mutually exclusive with
///   `force_zerocopy`; copy-mode takes precedence when both are set.
/// - `force_zerocopy` — forces zero-copy mode (`XDP_ZEROCOPY`).
/// - `inhibit_prog_load` — sets `XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD` to suppress
///   XDP program attachment. Required for `queue_id > 0` in multi-queue deployments
///   to avoid double-attaching the XDP program on the same interface.
pub fn build_socket_config(
    force_copy: bool,
    force_zerocopy: bool,
    inhibit_prog_load: bool,
) -> SocketConfig {
    let mut builder = SocketConfig::builder();
    let mut bind_flags = BindFlags::XDP_USE_NEED_WAKEUP;

    if force_copy {
        bind_flags.insert(BindFlags::XDP_COPY);
        tracing::info!("Forcing copy-mode (XDP_COPY)");
    } else if force_zerocopy {
        bind_flags.insert(BindFlags::XDP_ZEROCOPY);
        tracing::info!("Forcing zero-copy mode (XDP_ZEROCOPY)");
    }

    builder.bind_flags(bind_flags);

    if inhibit_prog_load {
        builder.libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD);
        tracing::info!("Inhibiting XDP program load (multi-queue: secondary queue)");
    }

    builder.build()
}

/// Populates a Fill Queue with all pre-allocated UMEM frame descriptors.
///
/// # Purpose
/// After UMEM construction and socket binding, every frame descriptor must be submitted
/// to the Fill Queue so the kernel can write incoming packets into them. This function
/// performs that submission and validates that all frames were accepted.
///
/// # Safety Invariants
/// * All frames in `frame_descs` must be **owned by the caller** and **not currently
///   in flight** on any ring. This invariant is trivially satisfied when called
///   immediately after [`build_umem`], before the packet loop starts.
/// * `fq` must correspond to the same UMEM that backs `frame_descs`.
///
/// # Errors
/// Returns an error if the Fill Queue accepts fewer frames than provided, which
/// indicates a ring capacity mismatch (`ring_size < frame_count`).
///
/// # Performance Rationale
/// Called once at startup. No packet loop interaction — this is purely initialization.
pub unsafe fn populate_fill_queue(
    fq: &mut FillQueue,
    frame_descs: &[FrameDesc],
) -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: All descriptors in frame_descs are owned and not in flight on any ring.
    // This is guaranteed by the caller's contract: called once after build_umem,
    // before the packet loop begins.
    let produced = fq.produce(frame_descs);
    if produced != frame_descs.len() {
        return Err(format!(
            "Failed to populate Fill Queue: produced {} out of {} frames",
            produced,
            frame_descs.len()
        )
        .into());
    }
    tracing::info!("Populated Fill Queue with all {} frames", produced);
    Ok(())
}

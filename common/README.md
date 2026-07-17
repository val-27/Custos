# Custos Common Utility Library

This crate provides shared utilities, constants, data structures, and thread-affinity configurations used across all processing phases of Custos.

## Components & Purpose

*   **UMEM Constants**: Defines the standard page and queue configurations:
    *   `UMEM_FRAME_SIZE = 2048`: Configured to fit standard Ethernet MTU frames.
    *   `UMEM_RING_SIZE = 2048`: Buffer ring size (must be a power of two).
*   **`OperationMode`**: An optimized enumeration of fast path modes:
    *   `Drop`: Directly drops and recycles incoming frame descriptors.
    *   `Forward`: Forwards packets unchanged.
    *   `Echo`: In-place swap of source and destination MAC addresses before forwarding.
*   **Thread Pinning (`pin_thread_to_core`)**: System-level bindings using `sched_setaffinity` on Linux to bind processing threads to dedicated CPU cores, preventing OS context switches and maximizing throughput.

## Platform Support

*   **Linux**: Full support for thread pinning (`sched_setaffinity` syscall).
*   **macOS / Other**: Compiles successfully with a fallback warning. Thread pinning is ignored during local macOS mock test execution.

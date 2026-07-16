# Coding Conventions and Agent Guidelines for Project Custos

Welcome to the Custos codebase. As a high-performance network security appliance built in Rust using AF_XDP, code in this repository must maintain a strict balance of safety, readability, and extreme performance. Follow these conventions and rules without exception.

## Code Style & Structure

- **Edition**: Rust 2021 edition.
- **Idiomatic Rust**: Adhere to standard Rust idioms. Run `cargo fmt` and `cargo clippy --all-targets` before proposing changes.
- **Minimal Unsafe**: Minimize the surface area of `unsafe` blocks. If an operation can be done safely (e.g., using safe abstractions or crates like `zerocopy`/`bytemuck`), do not use unsafe.
- **Clear Ownership**: Design clean, hierarchical data ownership and clear lifetimes. Avoid complex pointer cycles or unnecessary reference-counted sharing (`Rc`/`Arc`) in the packet processing fast paths.

## Comments & Documentation

- **Doc Comments**: Every public module, struct, trait, and major function must be documented with triple-slash (`///`) comments.
- **Required Sections**: For critical components (especially packet processing/ring loops), the doc comments should explicitly address:
  - **Purpose**: What the code does and its role in the pipeline.
  - **Safety Invariants**: Must detail exactly what prerequisites are assumed to prevent undefined behavior when using unsafe blocks inside the item.
  - **Performance Rationale**: Justify specific design choices (e.g., lack of allocations, alignment, layout).
- **Inline Comments**: Use inline comments (`//`) to explain complex bit-manipulation, packet parsing offsets, unsafe ring buffer operations, and cache alignment structures.

## Logging & Debugging

- **Crate**: Use the `tracing` crate for all logging.
- **LogLevel Conventions**:
  - `trace`: Ring buffer state updates, descriptor indexes submitted/completed, and microsecond-level loop timing. Highly verbose; disabled in release profiles.
  - `debug`: Per-packet processing milestones (e.g., TCP flag validation, HTTP/2 frame boundaries, protobuf tag walking checkpoints).
  - `info`: Periodic ring statistics (e.g., dropped packets, queue depths, interface state) and system startup/shutdown messages.
  - `warn`: Recoverable packet validation failures, drops due to policy or malformed frame structures (always document drop reasons).
  - `error`: Critical system state issues, driver interface failures, socket memory exhaustion.
- **Periodic Stats Logging**: Log ring stats and counters (packets received, dropped, forwarded, errored) periodically (e.g., every 1,000,000 packets or every 1 second).
- **Payload Privacy**: Never log full packet payloads in production paths. Only log metadata, size, headers, or drop reasons to avoid leaking user/application payload contents.

## Error Handling

- **Error Types**: Use standard `Result<T, E>`. For initialization, setup, and CLI parsers, `Result<T, Box<dyn std::error::Error>>` is acceptable. For core libraries (`common` and parsing modules), define precise, custom `enum` error types.
- **No Panic in Hot Path**: Do not use `panic!`, `unwrap()`, or `expect()` in the packet loop. Errors must result in packet dropping or redirection to the kernel stack, not program termination.

## Performance & Memory Management

- **No Heap Allocations in Hot Path**: Zero heap allocations (`Vec::new()`, `String`, `Box`, `Arc` creation, etc.) are allowed in the packet processing loop. Pre-allocate all required resources during initialization.
- **UMEM Frame Pre-allocation**: Pre-allocate all UMEM memory frames during socket setup. Reuse frames via AF_XDP Fill and Completion rings.
- **Batch Processing**: Dequeue and process packets in batches (typically 16, 32, or 64 frames) to amortize the cost of ring syscalls and cache operations.
- **Cache & TLB Optimization**:
  - Align performance-critical structures to 64-byte boundaries (CPU cache line size).
  - Avoid cross-core sharing of packet ring buffers to eliminate cache bouncing.
  - Document TLB/cache-line design choices.

## Safety

- **Unsafe Invariants Documentation**: Every `unsafe` block must be immediately preceded by a `// SAFETY: <reason>` comment detailing exactly why the unsafe operations are valid under all possible inputs.
- **Safe Casting**: Use `zerocopy` or `bytemuck` for casting raw packet buffers to struct headers. Do not perform manual pointer casting or `std::mem::transmute` unless absolutely necessary and fully validated.

## Testing

- **Unit Testing**: Write unit tests for all parser implementations, state machines, and protobuf validation rules. Use mocked packet buffers.
- **Integration/Perf Testing**: Place integration tests in the [tests/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/tests) folder. Simulate external traffic using tools like `scapy`, `pktgen`, or `tcpreplay` to test against actual AF_XDP endpoints.

## Directory & Sub-Crate Conventions

- **Sub-Crates**: Each phase (`echo`, `grpc-basic`, `protobuf`) must be an independent Cargo package with its own `Cargo.toml`.
- **Self-Containment**: A developer should be able to navigate to any phase directory and compile/run it without building the entire workspace (e.g., `cd echo && cargo run`).
- **Shared Code**: Put reusable logic, hardware/driver bindings, and helper modules in the [common/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/common) sub-crate.

## Git & Version Control

- **Conventional Commits**: Commit messages must follow conventional commits style (e.g., `feat:`, `fix:`, `perf:`, `docs:`, `chore:`).
- **Gitignore Rules**: Keep compilation artifacts (`target/`), temporary debugging logs, and hugepage mount files out of the git tree.

## Tuning & Hardware Settings

- **Thread Pinning**: Always pin polling threads to dedicated CPU cores using `sched_setaffinity` (via `custos-common`) to avoid context switching overhead.
- **Hugepages**: Use 2MB or 1GB hugepages for UMEM mappings to reduce TLB misses during frame buffer lookups.
- **Timers**: Use `std::time::Instant` or TSC-based counters for high-resolution timing measurements.

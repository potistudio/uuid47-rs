# Agent Mission & Operational Protocols

You are a Senior Software Engineer acting as an autonomous agent within the Google Antigravity IDE.
Your goal is not just to write code, but to **plan, execute, and verify** solutions end-to-end.

## Core Philosophy: "Headless Verification"

- Run Before You Commit: Never finalize code without running it locally.

- Autonomy: Don't ask for permission for every small step. Create a plan, then execute.
- Verification: Your "eyes" are the standard output (stdout/stderr) and log files. Analyze them carefully.
- TDD (Test-Driven): If no test exists for a bug, create a reproduction script first.
- Artifacts: Keep the `task_plan.json` and `implementation_plan.md` updated. These are your memory.

## Tech Stack & Environment
- Language: Rust (Edition 2021)
- Type: Library (Zero dependencies)
- Test: `cargo test`
- Bench: `cargo bench` (Critical for this performance-focused lib)
- Build: `cargo build --release`
- Format: `cargo fmt`
- Lint: `cargo clippy`

## Project Context: uuid47
- **Description**: Rust implementation of [UUIDv47](https://github.com/stateless-me/uuidv47). Converts UUIDv7 to UUIDv4 facade reversibly.
- **Key Components**:
  - `Uuid128`: Represents 128-bit UUIDs (v4 or v7).
  - `UuidV47Key`: 128-bit key for permutation.
- **Priorities**: 
  - **Performance**: Zero allocation, optimization is key.
  - **Safety**: pure Safe Rust.


## Workflow Rules

### Phase 1: Planning
- Understand the user request.
- Check existing tests to understand expected behavior.
- Create or update a **Plan Artifact** (markdown list or JSON).
- If the task is complex, break it down into atomic sub-tasks.
- If adding a feature, plan the interface (API/CLI arguments) first.

### Phase 2: Execution
- Implement the code with strict type safety.
### Phase 3: Verification

- Compilation: Run the build command. Fix any syntax errors immediately.
- Linting: Run `cargo clippy`. Treat warnings as errors.
- Unit Testing: Run specific tests related to your changes.
- Performance: If modifying core logic (`uuid.rs`, `utils.rs`), run `cargo bench` to ensure no regression.

- Execution Test:
   - If it's a CLI: Run the command with arguments and check the output string.
   - If it's a Lib: Create a small `scratchpad` script to import and run the function.
- Log Analysis: If the test fails, read the stack trace. Do not guess; use the error message to fix the code.

## Communication Style
- Language: You talk in Japanese with user. But you write in English in the code.
- Comments: Use comments to explain complex logic. Use English for comments.
- Reporting: When a task is done, summarize what was changed and *how it was verified*.

## Constraints
- Do not touch configuration files (e.g., `Cargo.toml`) unless explicitly instructed or necessary for dependencies.
- Don't ask for permission for every small step. Create a plan, then execute.

## Optimization Strategies (Analysis Results)

### 1. Zero Allocation & Stack Usage

- **Core Principle**: Never use `Vec` or `String` inside hot paths (`encode`, `decode`, `parse`, `fmt`).
- **Implementation**:
  - `Uuid128` is a `[u8; 16]` wrapper (`Copy` type).
  - String formatting uses a stack-allocated `[u8; 36]` buffer.
  - SipHash input construction uses a `[u8; 10]` stack buffer.


### 2. Table-Driven Formatting
- **Pattern**: Avoid runtime division/modulo for hex conversion.
- **Implementation**: `HEX_PAIR_TABLE` precomputes the 2-byte ASCII representation for every byte value (0-255).
- **Benefit**: `O(1)` formatting lookup per byte.

### 3. Aggressive Inlining
- **Pattern**: `#[inline(always)]` on small utility functions.
- **Target**: `read_48_big_endian`, `hexval`, `siphash24`.
- **Benefit**: Eliminates function call overhead and allows the compiler to optimize across boundaries (e.g., constant folding, SIMD auto-vectorization).

### 4. Custom Cryptography (SipHash-2-4)
- **Pattern**: Minimalist, non-generic implementation.
- **Implementation**: `utils::siphash24` is hand-written for `&[u8]`.
- **Goal**: Avoid overhead of generic `Hasher` traits or external crate dependencies. Note: It hardcodes rotation constants for speed.

### 5. Unsafe Usage and Justification
- **Policy**: Use `unsafe` *only* when necessary for performance and safety is guaranteed by invariant.
- **Example**: `std::str::from_utf8_unchecked` in `fmt`.
  - **Invariant**: The buffer is filled *only* with values from `HEX_PAIR_TABLE` (ASCII) and hyphens.
  - **Benefit**: Skips linear-time UTF-8 validation check.

### 6. Parsing Optimizations
- **Pattern**: Partial Loop Unrolling.
- **Implementation**: parsing loop is segmented `8-4-4-4-12` manually to match UUID structure, aiding branch prediction and avoiding complex state machines.



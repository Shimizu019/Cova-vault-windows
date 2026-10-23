# Cova Vault — Windows

A local-first password vault for Windows, built with **Tauri 2**, **React 19**,
**TypeScript**, **Vite**, and **Tailwind CSS v3**.

> **Status: Milestone 1 — application shell only.**
> This repository currently contains the branded desktop shell and its NSIS
> installer. Authentication, encryption, persistence, and all vault features are
> intentionally **not** implemented yet.

---

## Requirements

| Tool         | Version           |
| ------------ | ----------------- |
| Node.js      | 20.19+ / 22.12+   |
| npm          | 10+               |
| Rust         | 1.90+ (edition 2024) |
| MSVC Build Tools | Visual Studio 2022 (Desktop C++ workload) |
| Windows SDK  | 10.0.17763+       |
| WebView2     | Evergreen (preinstalled on Windows 10/11) |
| Python       | 3.9+ with Pillow — only for regenerating icons |

## Getting started

```bash
npm install
npm run tauri:dev      # launches the native window with hot reload
```

## Scripts

| Script                 | Description                                              |
| ---------------------- | -------------------------------------------------------- |
| `npm run dev`          | Vite dev server only (http://localhost:1420)              |
| `npm run build`        | Type-check + production frontend build into `dist/`       |
| `npm run typecheck`    | `tsc -b --pretty`                                         |
| `npm run lint`         | ESLint (flat config)                                      |
| `npm run verify`       | typecheck → lint → build                                  |
| `npm run tauri:dev`    | Run the desktop app in development mode                   |
| `npm run tauri:build`  | **Build the NSIS installer**                              |
| `npm run icon:source`  | Regenerate `src-tauri/icons/icon-source.png` from `lockLogo.png` |
| `npm run icon:generate`| Regenerate the full Tauri icon set from `icon-source.png` |

## Building the installer

```bash
npm run tauri:build
```

The installer is written to:

```
src-tauri/target/release/bundle/nsis/Cova Vault_0.1.0_x64-setup.exe
```

NSIS is configured with `installMode: "both"`, so the user can choose a
per-user or per-machine install at install time.

### ⚠️ Building the Rust crate directly

Do **not** use a bare `cargo build --release` if you intend to run the
resulting binary. The `tauri` crate only embeds the frontend assets when the
`custom-protocol` Cargo feature is enabled; the Tauri CLI turns it on
automatically, but plain Cargo does not. A binary built that way silently
tries to load `http://localhost:1420` at runtime and shows a
"can't reach this page" error.

Use the aliases provided in `src-tauri/.cargo/config.toml` instead:

```bash
cd src-tauri
cargo build-release      # release binary with embedded assets
cargo build-debug        # debug binary with embedded assets
```

`npm run tauri:build` is always the canonical way to produce an installer.

## Branding

| Asset                | Purpose                              |
| -------------------- | ------------------------------------ |
| `lockLogo.png`       | Application / installer icon source  |
| `CovaLogo.png`       | Wordmark used on the opening screen  |
| `public/brand/`      | Runtime copies of both assets        |
| `src-tauri/icons/`   | Generated icon set (1024 → 32 px)    |

`scripts/make-icon-source.py` builds a padded 1024×1024 transparent canvas
from `lockLogo.png` so the mark is not cropped by the Windows icon mask. The
original PNGs are never modified.

## Design tokens

Dark-first palette defined as CSS RGB triplets in `src/index.css`, so Tailwind
opacity modifiers (`bg-primary/20`) work as expected.

| Token            | Value     |
| ---------------- | --------- |
| Background       | `#07111F` |
| Surface          | `#0D1B2A` |
| Elevated surface | `#12263A` |
| Border           | `#20364D` |
| Primary          | `#2F80FF` |
| Accent           | `#3FA9FF` |
| Violet           | `#8B5CF6` |
| Primary text     | `#F5F9FF` |
| Secondary text   | `#A5B8CB` |

## Security posture

This milestone deliberately ships **no** vault or credential functionality:

- No authentication, encryption, or key derivation.
- No filesystem, store, shell, or network plugins.
- No telemetry, cloud access, or updater.
- The only granted capability is Tauri's minimal `core:default` set, scoped to
  the single `main` window.
- A restrictive Content Security Policy is configured in `tauri.conf.json`.

Any authentication, KDF, or backup code must be written from scratch for this
repository — it must **not** be copied from the GPL-3.0 Android project, whose
insecure patterns are explicitly out of scope here.

## License

MIT — see [LICENSE](./LICENSE).

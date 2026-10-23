/**
 * Milestone 1 opening screen.
 *
 * This is the application shell only: it proves the desktop window renders and
 * carries the Cova brand. No vault, authentication, or persistence behaviour is
 * implemented yet, and no security capability is implied.
 */

const BRAND_GLOW = {
  background:
    'radial-gradient(58% 46% at 50% 40%, rgba(47, 128, 255, 0.18) 0%, rgba(139, 92, 246, 0.09) 48%, transparent 76%)',
}

export default function App() {
  return (
    <main className="relative flex min-h-full w-full items-center justify-center overflow-hidden bg-cova-bg px-8 py-12 text-cova-text">
      {/* Restrained brand glow, drawn from the Cova blue -> violet sweep. */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0" style={BRAND_GLOW} />

      <div className="relative flex w-full max-w-md flex-col items-center text-center">
        <img
          src="/brand/CovaLogo.png"
          alt="Cova Vault"
          width={866}
          height={288}
          className="w-full max-w-[19rem] select-none"
          draggable={false}
        />

        <div
          aria-hidden="true"
          className="mt-9 h-px w-40 bg-gradient-to-r from-transparent via-cova-primary to-transparent"
        />

        <h1 className="mt-7 text-2xl font-semibold tracking-tightest text-cova-text">
          Cova Vault
        </h1>
        <p className="mt-2 text-sm leading-relaxed text-cova-muted">
          Local-first by design. Built for Windows.
        </p>

        <div className="mt-9 inline-flex items-center gap-2.5 rounded-badge border border-cova-border bg-cova-surface/70 px-4 py-2">
          <span className="relative flex h-2 w-2" aria-hidden="true">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cova-accent opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-cova-accent" />
          </span>
          <span className="text-xs font-medium tracking-wide text-cova-muted">
            Windows preview
          </span>
        </div>

        <p className="mt-10 max-w-sm text-xs leading-relaxed text-cova-faint">
          Milestone 1 &mdash; application shell. Vault features are not implemented yet.
        </p>
      </div>
    </main>
  )
}

/**
 * Custom inline SVG logo for SentinelScope.
 * Geometric shield with a precision aperture — security + observation.
 * Monochrome (currentColor) so it inherits sidebar/foreground.
 */
export function Logo({ size = 28, withWordmark = true }: { size?: number; withWordmark?: boolean }) {
  return (
    <div className="flex items-center gap-2.5" aria-label="SentinelScope" data-testid="brand-logo">
      <svg
        width={size}
        height={size}
        viewBox="0 0 32 32"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-hidden="true"
      >
        <path
          d="M16 4 L26 7.5 V16 C26 21.4 21.8 25.2 16 28 C10.2 25.2 6 21.4 6 16 V7.5 Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <circle cx="16" cy="15" r="3.6" stroke="currentColor" strokeWidth="1.6" />
        <line x1="16" y1="15" x2="22.5" y2="8.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        <circle cx="16" cy="15" r="1.1" fill="currentColor" />
      </svg>
      {withWordmark && (
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight">SentinelScope</div>
          <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Authorized Recon</div>
        </div>
      )}
    </div>
  );
}

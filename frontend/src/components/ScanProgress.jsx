export default function ScanProgress({ scan }) {
  const pct = scan?.progress_pct ?? 0;
  const msg = scan?.progress_message ?? "Starting...";
  const target = scan?.target_url ?? "";

  return (
    <div style={{ background: "#0d1117", border: "1px solid #1f6feb44", borderRadius: 14, padding: 28, marginBottom: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#388bfd", marginBottom: 4, fontFamily: "Fira Code" }}>
            ◉ SCAN IN PROGRESS
          </div>
          <div style={{ fontSize: 12, color: "#8b949e", fontFamily: "Fira Code" }}>{target}</div>
        </div>
        <div style={{ fontFamily: "Fira Code", fontSize: 22, fontWeight: 700, color: "#388bfd" }}>
          {pct}%
        </div>
      </div>

      <div style={{ height: 6, background: "#161b22", borderRadius: 99, marginBottom: 12, overflow: "hidden" }}>
        <div style={{
          height: "100%", width: `${pct}%`,
          background: "linear-gradient(90deg, #1f6feb, #388bfd)",
          borderRadius: 99, transition: "width 0.4s ease",
        }} />
      </div>

      <div style={{ fontSize: 12, color: "#8b949e" }}>
        {msg}
      </div>

      {/* Animated dots */}
      <div style={{ display: "flex", gap: 4, marginTop: 12 }}>
        {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((i) => (
          <div key={i} style={{
            width: 6, height: 6, borderRadius: "50%",
            background: i < Math.floor(pct / 10) ? "#388bfd" : "#21262d",
            transition: "background 0.3s",
          }} />
        ))}
      </div>
    </div>
  );
}

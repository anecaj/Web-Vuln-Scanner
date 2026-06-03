export default function ScanHistory({ scans, onSelect, currentId }) {
  if (scans.length === 0) return null;

  const riskColor = (scan) => {
    if (scan.critical_count > 0) return "#ff4d4d";
    if (scan.high_count     > 0) return "#fb923c";
    if (scan.medium_count   > 0) return "#fbbf24";
    return "#4ade80";
  };

  return (
    <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 12, padding: 16 }}>
      <div style={{ fontSize: 11, color: "#484f58", fontFamily: "Fira Code", marginBottom: 12, letterSpacing: "0.08em" }}>
        SCAN HISTORY
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {scans.map((s) => (
          <div
            key={s.scan_id}
            onClick={() => onSelect(s.scan_id)}
            style={{
              padding: "8px 10px", borderRadius: 8, cursor: "pointer",
              border: `1px solid ${currentId === s.scan_id ? "#30363d" : "#161b22"}`,
              background: currentId === s.scan_id ? "#161b22" : "transparent",
              transition: "all 0.1s",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
              <span style={{ fontSize: 12, color: "#c9d1d9", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "70%" }}>
                {s.target_url.replace(/^https?:\/\//, "")}
              </span>
              <span style={{ fontSize: 11, color: riskColor(s), fontFamily: "Fira Code", fontWeight: 700 }}>
                {s.total_findings}
              </span>
            </div>
            <div style={{ fontSize: 10, color: "#484f58" }}>
              {s.status === "running" ? "🔄 Running..." : new Date(s.started_at).toLocaleDateString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

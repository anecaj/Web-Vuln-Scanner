const SEV_CONFIG = [
  { key: "critical_count", label: "CRITICAL", color: "#ff4d4d" },
  { key: "high_count",     label: "HIGH",     color: "#fb923c" },
  { key: "medium_count",   label: "MEDIUM",   color: "#fbbf24" },
  { key: "low_count",      label: "LOW",      color: "#4ade80" },
  { key: "info_count",     label: "INFO",     color: "#60a5fa" },
];

export default function SeveritySummary({ scan }) {
  const total = scan.total_findings || 0;
  const hasCritical = (scan.critical_count || 0) > 0;
  const hasHigh     = (scan.high_count || 0) > 0;

  const overallRisk = hasCritical ? "CRITICAL" : hasHigh ? "HIGH" :
    (scan.medium_count || 0) > 0 ? "MEDIUM" : "LOW";
  const riskColor = { CRITICAL: "#ff4d4d", HIGH: "#fb923c", MEDIUM: "#fbbf24", LOW: "#4ade80" }[overallRisk];

  return (
    <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 12, padding: 20, marginBottom: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 11, color: "#484f58", fontFamily: "Fira Code", marginBottom: 4 }}>SCAN COMPLETE</div>
          <div style={{ fontSize: 13, color: "#8b949e", fontFamily: "Fira Code" }}>{scan.target_url}</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontFamily: "Fira Code", fontSize: 28, fontWeight: 700, color: riskColor, lineHeight: 1 }}>
            {total}
          </div>
          <div style={{ fontSize: 11, color: "#484f58" }}>findings</div>
        </div>
      </div>

      {/* Overall risk badge */}
      <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: `${riskColor}15`, border: `1px solid ${riskColor}44`, borderRadius: 99, padding: "5px 14px", marginBottom: 16 }}>
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: riskColor }} />
        <span style={{ fontSize: 12, color: riskColor, fontFamily: "Fira Code", fontWeight: 600 }}>
          OVERALL RISK: {overallRisk}
        </span>
      </div>

      {/* Severity breakdown */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {SEV_CONFIG.map(({ key, label, color }) => {
          const count = scan[key] || 0;
          return (
            <div key={key} style={{
              flex: 1, minWidth: 70, background: "#010409",
              border: `1px solid ${count > 0 ? color + "44" : "#21262d"}`,
              borderRadius: 8, padding: "10px 12px", textAlign: "center",
            }}>
              <div style={{ fontFamily: "Fira Code", fontSize: 20, fontWeight: 700, color: count > 0 ? color : "#484f58" }}>
                {count}
              </div>
              <div style={{ fontSize: 10, color: "#484f58", marginTop: 2 }}>{label}</div>
            </div>
          );
        })}
      </div>

      {/* Duration */}
      {scan.started_at && scan.completed_at && (
        <div style={{ fontSize: 11, color: "#484f58", marginTop: 12, fontFamily: "Fira Code" }}>
          Duration: {Math.round((new Date(scan.completed_at) - new Date(scan.started_at)) / 1000)}s •
          Completed: {new Date(scan.completed_at).toLocaleString()}
        </div>
      )}
    </div>
  );
}

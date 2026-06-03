import { useState } from "react";

const SEV = {
  CRITICAL: { bg: "#2d0f0f", text: "#ff4d4d", border: "#7f1d1d", dot: "#ff4d4d" },
  HIGH:     { bg: "#2d1a0f", text: "#fb923c", border: "#7c2d12", dot: "#fb923c" },
  MEDIUM:   { bg: "#2d250f", text: "#fbbf24", border: "#78350f", dot: "#fbbf24" },
  LOW:      { bg: "#0f2215", text: "#4ade80", border: "#14532d", dot: "#4ade80" },
  INFO:     { bg: "#0f1a2d", text: "#60a5fa", border: "#1e3a5f", dot: "#60a5fa" },
};

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(finding.severity === "CRITICAL" || finding.severity === "HIGH");
  const s = SEV[finding.severity] || SEV.INFO;

  return (
    <div style={{
      background: s.bg, border: `1px solid ${s.border}`,
      borderRadius: 10, marginBottom: 10, overflow: "hidden",
    }}>
      {/* Header */}
      <div
        onClick={() => setOpen((o) => !o)}
        style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", cursor: "pointer" }}
      >
        <div style={{ width: 8, height: 8, borderRadius: "50%", background: s.dot, flexShrink: 0 }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#f0f6fc" }}>{finding.check_name}</div>
          <div style={{ fontSize: 11, color: "#8b949e", marginTop: 2 }}>{finding.category} • {finding.owasp}</div>
        </div>
        <span style={{
          fontSize: 10, padding: "3px 10px", borderRadius: 99,
          background: "rgba(0,0,0,0.3)", color: s.text,
          fontFamily: "Fira Code", fontWeight: 700, letterSpacing: "0.05em",
        }}>
          {finding.severity}
        </span>
        <span style={{ color: "#484f58", fontSize: 12, marginLeft: 4 }}>{open ? "▲" : "▼"}</span>
      </div>

      {/* Body */}
      {open && (
        <div style={{ padding: "0 16px 16px", borderTop: `1px solid ${s.border}` }}>
          <div style={{ paddingTop: 14 }}>
            <div style={{ fontSize: 12, color: "#c9d1d9", lineHeight: 1.7, marginBottom: 14 }}>
              {finding.description}
            </div>

            {finding.evidence && (
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 10, color: "#484f58", fontFamily: "Fira Code", marginBottom: 6 }}>EVIDENCE</div>
                <div style={{ fontFamily: "Fira Code", fontSize: 11, color: s.text, background: "rgba(0,0,0,0.3)", padding: "8px 12px", borderRadius: 6, lineHeight: 1.5 }}>
                  {finding.evidence}
                </div>
              </div>
            )}

            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: "#484f58", fontFamily: "Fira Code", marginBottom: 6 }}>REMEDIATION</div>
              <div style={{ fontSize: 12, color: "#8b949e", lineHeight: 1.6 }}>{finding.remediation}</div>
            </div>

            {finding.cwe && (
              <div style={{ fontSize: 10, color: "#484f58", fontFamily: "Fira Code", marginTop: 8 }}>
                {finding.cwe}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

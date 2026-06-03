import { useState } from "react";

const EXAMPLES = [
  "http://testphp.vulnweb.com",
  "https://httpbin.org",
  "https://example.com",
];

export default function ScanForm({ onScan, loading }) {
  const [url, setUrl] = useState("");

  function submit(targetUrl) {
    const u = targetUrl || url;
    if (!u.trim()) return;
    onScan(u.trim());
  }

  return (
    <div style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 14, padding: 28, marginBottom: 24 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 22, fontWeight: 600, color: "#f0f6fc", marginBottom: 6 }}>
          🔍 VulnScope
        </div>
        <div style={{ fontSize: 13, color: "#8b949e", lineHeight: 1.6 }}>
          OWASP-aligned web vulnerability scanner. Checks for 10+ vulnerability classes including XSS,
          SQL injection, security header misconfigurations, cookie security, CORS, and more.
        </div>
        <div style={{ marginTop: 10, padding: "8px 12px", background: "#161b22", border: "1px solid #f59e0b33", borderRadius: 8, fontSize: 11, color: "#f59e0b" }}>
          ⚠ Only scan websites you own or have explicit written permission to test. Unauthorized scanning may be illegal.
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder="https://your-website.com"
          style={{
            flex: 1, background: "#010409", border: "1px solid #30363d",
            borderRadius: 8, padding: "12px 16px", color: "#c9d1d9",
            fontFamily: "Fira Code", fontSize: 13, outline: "none",
          }}
        />
        <button
          onClick={() => submit()}
          disabled={loading || !url.trim()}
          style={{
            padding: "12px 28px", background: loading ? "#21262d" : "linear-gradient(135deg, #1f6feb, #388bfd)",
            border: "none", borderRadius: 8, color: loading ? "#484f58" : "#fff",
            fontFamily: "Fira Code", fontSize: 13, fontWeight: 600,
            cursor: loading ? "not-allowed" : "pointer", whiteSpace: "nowrap",
          }}
        >
          {loading ? "Scanning..." : "Run Scan →"}
        </button>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: "#484f58", fontFamily: "Fira Code" }}>EXAMPLES:</span>
        {EXAMPLES.map((e) => (
          <button key={e} onClick={() => { setUrl(e); submit(e); }} style={{
            background: "transparent", border: "1px solid #21262d", borderRadius: 99,
            padding: "3px 10px", color: "#8b949e", fontSize: 11, fontFamily: "Fira Code",
            cursor: "pointer",
          }}>
            {e.replace(/^https?:\/\//, "")}
          </button>
        ))}
      </div>
    </div>
  );
}

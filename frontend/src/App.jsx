import { useState, useEffect, useRef } from "react";
import { startScan, getScan, listScans } from "./api";
import ScanForm        from "./components/ScanForm";
import ScanProgress    from "./components/ScanProgress";
import SeveritySummary from "./components/SeveritySummary";
import FindingCard     from "./components/FindingCard";
import ScanHistory     from "./components/ScanHistory";

const css = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #010409; color: #c9d1d9; font-family: 'Inter', sans-serif; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #010409; }
  ::-webkit-scrollbar-thumb { background: #21262d; border-radius: 4px; }
`;

export default function App() {
  const [scanning, setScanning]   = useState(false);
  const [scanData, setScanData]   = useState(null);
  const [history, setHistory]     = useState([]);
  const [filter, setFilter]       = useState("ALL");
  const [error, setError]         = useState("");
  const pollRef                   = useRef(null);

  useEffect(() => {
    listScans().then((r) => setHistory(r.data)).catch(() => {});
    return () => clearInterval(pollRef.current);
  }, []);

  async function handleScan(url) {
    setError(""); setScanning(true); setScanData(null);
    try {
      const res = await startScan(url);
      const { scan_id } = res.data;
      setScanData(res.data);
      pollRef.current = setInterval(async () => {
        const poll = await getScan(scan_id);
        setScanData(poll.data);
        if (poll.data.status !== "running") {
          clearInterval(pollRef.current);
          setScanning(false);
          listScans().then((r) => setHistory(r.data)).catch(() => {});
        }
      }, 2000);
    } catch (e) {
      setError(e.response?.data?.error || "Scan failed — check the URL and try again");
      setScanning(false);
    }
  }

  async function loadScan(scan_id) {
    const res = await getScan(scan_id);
    setScanData(res.data);
    setFilter("ALL");
  }

  const findings = scanData?.findings || [];
  const SEVERITIES = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const filtered = filter === "ALL" ? findings : findings.filter((f) => f.severity === filter);

  const SEV_COLORS = { CRITICAL: "#ff4d4d", HIGH: "#fb923c", MEDIUM: "#fbbf24", LOW: "#4ade80", INFO: "#60a5fa" };

  return (
    <>
      <style>{css}</style>

      {/* Header */}
      <header style={{ borderBottom: "1px solid #21262d", padding: "0 32px", display: "flex", alignItems: "center", height: 52, gap: 12 }}>
        <span style={{ fontFamily: "Fira Code", fontWeight: 600, fontSize: 15, color: "#f0f6fc" }}>🔍 VulnScope</span>
        <span style={{ fontSize: 11, color: "#484f58", fontFamily: "Fira Code" }}>Web Vulnerability Scanner</span>
        <div style={{ marginLeft: "auto", fontSize: 11, color: "#484f58" }}>OWASP Top 10 Aligned</div>
      </header>

      <main style={{ padding: "28px 32px", maxWidth: 1200, margin: "0 auto" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 240px", gap: 24, alignItems: "start" }}>

          <div>
            <ScanForm onScan={handleScan} loading={scanning} />

            {error && (
              <div style={{ background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.2)", borderRadius: 10, padding: "12px 16px", marginBottom: 20, fontSize: 13, color: "#ff4d4d" }}>
                {error}
              </div>
            )}

            {scanning && scanData?.status === "running" && <ScanProgress scan={scanData} />}

            {scanData?.status === "error" && (
              <div style={{ background: "rgba(255,77,77,0.08)", border: "1px solid rgba(255,77,77,0.2)", borderRadius: 10, padding: "16px 20px", marginBottom: 20 }}>
                <div style={{ fontSize: 13, color: "#ff4d4d", marginBottom: 4 }}>Scan Failed</div>
                <div style={{ fontSize: 12, color: "#8b949e" }}>{scanData.error_msg}</div>
              </div>
            )}

            {scanData?.status === "complete" && (
              <>
                <SeveritySummary scan={scanData} />

                {/* Filter bar */}
                <div style={{ display: "flex", gap: 6, marginBottom: 16, flexWrap: "wrap" }}>
                  {SEVERITIES.map((s) => {
                    const count = s === "ALL" ? findings.length :
                      findings.filter((f) => f.severity === s).length;
                    return (
                      <button key={s} onClick={() => setFilter(s)} style={{
                        padding: "5px 14px", border: "1px solid",
                        borderColor: filter === s ? (SEV_COLORS[s] || "#388bfd") : "#21262d",
                        borderRadius: 99, background: "transparent", cursor: "pointer",
                        color: filter === s ? (SEV_COLORS[s] || "#388bfd") : "#484f58",
                        fontFamily: "Fira Code", fontSize: 11,
                      }}>
                        {s} {count > 0 && `(${count})`}
                      </button>
                    );
                  })}
                </div>

                {/* Findings */}
                {filtered.length === 0 ? (
                  <div style={{ textAlign: "center", padding: 40, color: "#484f58", fontSize: 13 }}>
                    No {filter !== "ALL" ? filter : ""} findings
                  </div>
                ) : (
                  filtered.map((f, i) => <FindingCard key={i} finding={f} />)
                )}
              </>
            )}
          </div>

          {/* Sidebar */}
          <div>
            <ScanHistory scans={history} onSelect={loadScan} currentId={scanData?.scan_id} />
          </div>
        </div>
      </main>
    </>
  );
}

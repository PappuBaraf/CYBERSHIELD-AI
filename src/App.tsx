import React, { useState } from "react";
import { ScanResult, scanContract } from "./scan";

const App: React.FC = () => {
  const [address, setAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!address) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await scanContract(address.trim());
      setResult(res);
    } catch (e: any) {
      setError(e.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full relative overflow-hidden bg-[#05050A] text-white">
      <div className="absolute inset-0 opacity-[0.06] bg-[url('/grid.svg')] bg-repeat" />
      <div className="relative z-10 max-w-4xl mx-auto px-6 py-20">
        {loading && !result && (
          <div className="text-center flex flex-col items-center">
            <div className="text-gray-400">Scan in progress…</div>
          </div>
        )}

        {!result && !loading && (
          <div className="text-center flex flex-col items-center">
            <h1 className="text-5xl md:text-6xl font-bold tracking-tight">
              Contract<span className="text-purple-400">Scan</span>
            </h1>
            <p className="text-gray-400 mt-4 text-lg max-w-xl">
              Analyze smart contract risks instantly through a Redis + Queue + Worker
              powered backend using only free, public APIs.
            </p>
            <div className="mt-10 w-full max-w-2xl flex bg-[#0B0B12] border border-gray-700 rounded-xl px-4 py-3 shadow-lg">
              <input
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="Paste contract address (0x...)"
                className="bg-transparent w-full text-white placeholder-gray-500 text-sm outline-none"
              />
              <button
                onClick={handleScan}
                disabled={loading}
                className="bg-purple-600 hover:bg-purple-700 ml-3 px-6 rounded-lg text-sm font-medium"
              >
                {loading ? "Scanning..." : "Analyze"}
              </button>
            </div>
            {error && (
              <div className="mt-4 text-sm text-red-400 bg-red-950/40 border border-red-600/40 px-3 py-2 rounded-lg">
                {error}
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="space-y-10">
            {result.status === "error" ? (
              <div className="text-center">
                <div className="text-red-400 text-lg">Scan failed: {result.reason}</div>
                <button
                  onClick={() => {
                    setResult(null);
                    setAddress("");
                  }}
                  className="mt-4 text-sm text-gray-400 hover:text-purple-300 underline"
                >
                  Try again
                </button>
              </div>
            ) : (
              <>
                <div>
                  <h2 className="text-3xl font-bold">
                    Results for{" "}
                    <span className="text-purple-400 break-all">
                      {result.result?.address}
                    </span>
                  </h2>
                  <p className="text-gray-400 mt-2">
                    Combined on-chain and metadata view. Processed via job queue.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                  <div className="space-y-6">
                    <ResultCard title="Overview">
                      <Info label="Risk Score" value={result.result?.riskScore} />
                      <Info label="Verified" value={result.result?.verified ? "Yes" : "No"} />
                      <Info label="Name" value={result.result?.name ?? "Unknown"} />
                      <Info label="Symbol" value={result.result?.symbol ?? "-"} />
                      <Info
                        label="Total Supply"
                        value={
                          result.result?.totalSupply
                            ? result.result.totalSupply.toLocaleString()
                            : "-"
                        }
                      />
                    </ResultCard>

                    <ResultCard title="Providers">
                      <div className="flex flex-wrap gap-2 text-xs">
                        {result.result?.providers?.sourcify && <Row label="Sourcify" />}
                        {result.result?.providers?.dexscreener && <Row label="DexScreener" />}
                        {result.result?.providers?.coingecko && <Row label="CoinGecko" />}
                        {result.result?.providers?.goplus && <Row label="GoPlus" />}
                        {result.result?.providers?.surfacescan && <Row label="SurfaceScan" />}
                        {result.result?.providers?.thegraph && <Row label="TheGraph" />}
                        {result.result?.providers?.dune && <Row label="Dune" />}
                        {result.result?.providers?.rpc && <Row label="RPC" />}
                      </div>
                    </ResultCard>
                  </div>

                  <div className="md:col-span-2 space-y-6">
                    <ResultCard title="Risk Flags">
                      {(!result.result?.flags || result.result.flags.length === 0) && (
                        <div className="text-gray-500 text-sm">
                          No major risks detected in this scan.
                        </div>
                      )}
                      {result.result?.flags?.map((f: string, i: number) => (
                        <div key={i} className="text-sm text-gray-200">
                          • {f}
                        </div>
                      ))}
                    </ResultCard>

                    <ResultCard title="Market Data">
                      <div className="text-sm text-gray-200 space-y-1">
                        <Info
                          label="Price (USD)"
                          value={
                            result.result?.priceUsd != null
                              ? `$${result.result.priceUsd.toFixed(4)}`
                              : "-"
                          }
                        />
                        <Info
                          label="24h Change"
                          value={
                            result.result?.priceChange24h != null
                              ? `${result.result.priceChange24h.toFixed(2)}%`
                              : "-"
                          }
                        />
                        <Info
                          label="Liquidity (est.)"
                          value={
                            result.result?.liquidityUsd != null
                              ? `$${result.result.liquidityUsd.toLocaleString()}`
                              : "-"
                          }
                        />
                      </div>
                    </ResultCard>

                    <ResultCard title="Queue Info">
                      <p className="text-xs text-gray-400">
                        If Redis is configured (REDIS_URL), scans are processed through a BullMQ
                        queue + worker. Without Redis, the server falls back to direct processing
                        but keeps the same response shape.
                      </p>
                    </ResultCard>
                  </div>
                </div>

                <button
                  onClick={() => {
                    setResult(null);
                    setAddress("");
                  }}
                  className="text-sm text-gray-400 hover:text-purple-300 underline"
                >
                  New scan
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

const ResultCard: React.FC<{ title: string; children: React.ReactNode }> = ({
  title,
  children,
}) => (
  <div className="bg-[#0D0D15] border border-gray-800 rounded-xl p-6 backdrop-blur">
    <h3 className="text-lg font-semibold mb-4">{title}</h3>
    <div>{children}</div>
  </div>
);

const Info: React.FC<{ label: string; value: any }> = ({ label, value }) => (
  <div className="flex justify-between text-sm py-1">
    <span className="text-gray-400">{label}</span>
    <span className="text-gray-200">{value}</span>
  </div>
);

const Row: React.FC<{ label: string }> = ({ label }) => (
  <span className="px-2 py-1 rounded-md border border-emerald-500 text-emerald-300">
    {label}
  </span>
);

export default App;

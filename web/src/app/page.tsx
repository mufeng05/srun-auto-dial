"use client";

import { useCallback, useEffect, useState } from "react";
import { getStatus, getStatusMacvlan, type StatusResult } from "@/lib/api";
import { InterfaceSelect } from "@/components/interface-select";
import { StatusCard } from "@/components/status-card";

type Mode = "local" | "macvlan";

export default function Dashboard() {
  const [mode, setMode] = useState<Mode>("local");
  const [iface, setIface] = useState("");
  const [macAddress, setMacAddress] = useState("");
  const [status, setStatus] = useState<StatusResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!iface) return;
    if (mode === "macvlan" && !macAddress) return;
    setLoading(true);
    setError(null);
    const res =
      mode === "local"
        ? await getStatus(iface)
        : await getStatusMacvlan(iface, macAddress);
    if (res.success && res.data) {
      setStatus(res.data);
    } else {
      setError(res.error || "Failed to fetch status");
    }
    setLoading(false);
  }, [iface, mode, macAddress]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-2 text-sm text-neutral-400">
          Monitor your campus network connection status.
        </p>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-1 rounded-lg border border-neutral-800 bg-neutral-900/50 p-1 w-fit">
        {(["local", "macvlan"] as Mode[]).map((m) => (
          <button
            key={m}
            onClick={() => { setMode(m); setStatus(null); setError(null); }}
            className={`rounded-md px-4 py-2 text-sm font-medium transition-colors ${
              mode === m
                ? "bg-neutral-800 text-white"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            {m === "local" ? "Local" : "Macvlan"}
          </button>
        ))}
      </div>

      <InterfaceSelect
        value={iface}
        onChange={setIface}
        label={mode === "local" ? "Network Interface" : "Parent Interface"}
      />

      {mode === "macvlan" && (
        <div className="flex flex-col gap-2">
          <label className="text-sm text-neutral-400">MAC Address</label>
          <input
            type="text"
            placeholder="AA:BB:CC:DD:EE:FF"
            value={macAddress}
            onChange={(e) => setMacAddress(e.target.value)}
            className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-2.5 text-sm text-white placeholder-neutral-600 outline-none transition-colors focus:border-neutral-600 font-[family-name:var(--font-geist-mono)]"
          />
        </div>
      )}

      <StatusCard status={status} loading={loading} error={error} />

      <button
        onClick={fetchStatus}
        disabled={loading}
        className="rounded-lg border border-neutral-700 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:border-neutral-500 hover:bg-neutral-900 disabled:opacity-40"
      >
        Refresh
      </button>
    </div>
  );
}

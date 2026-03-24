"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { logoutLocal, logoutMacvlan } from "@/lib/api";
import { InterfaceSelect } from "@/components/interface-select";

type Mode = "local" | "macvlan";

export default function LogoutPage() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("local");
  const [iface, setIface] = useState("");
  const [macAddress, setMacAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogout = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);

    const res =
      mode === "local"
        ? await logoutLocal(iface)
        : await logoutMacvlan(iface, macAddress);

    setLoading(false);
    if (res.success) {
      setSuccess(true);
    } else {
      setError(res.error || "Logout failed");
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Logout</h1>
        <p className="mt-2 text-sm text-neutral-400">
          Disconnect from the campus network.
        </p>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-1 rounded-lg border border-neutral-800 bg-neutral-900/50 p-1 w-fit">
        {(["local", "macvlan"] as Mode[]).map((m) => (
          <button
            key={m}
            onClick={() => {
              setMode(m);
              setSuccess(false);
              setError(null);
            }}
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

      <form onSubmit={handleLogout} className="space-y-5">
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

        <button
          type="submit"
          disabled={loading || !iface || (mode === "macvlan" && !macAddress)}
          className="rounded-lg border border-red-900 bg-red-950/30 px-5 py-2.5 text-sm font-medium text-red-400 transition-colors hover:bg-red-950/50 hover:border-red-800 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading ? "Logging out..." : "Logout"}
        </button>
      </form>

      {success && (
        <div className="rounded-xl border border-green-900/50 bg-green-950/20 p-6 space-y-2">
          <p className="text-sm font-medium text-green-400">Logout successful</p>
          <button
            onClick={() => router.push("/")}
            className="mt-2 text-sm text-neutral-400 underline underline-offset-4 hover:text-white transition-colors"
          >
            Go to Dashboard
          </button>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-6">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}
    </div>
  );
}

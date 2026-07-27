export type ConnectionStatus = "connected" | "connecting" | "offline";

const styles: Record<ConnectionStatus, { dot: string; text: string; label: string }> = {
  connected: { dot: "bg-emerald-500", text: "text-emerald-700", label: "Connected" },
  connecting: { dot: "bg-amber-500", text: "text-amber-700", label: "Connecting…" },
  offline: { dot: "bg-neutral-400", text: "text-neutral-600", label: "Offline" },
};

// Connection status is mocked/hardcoded for now — real Plaste API wiring is a
// follow-up integration task, out of scope here.
export function StatusBadge({ status }: { status: ConnectionStatus }) {
  const s = styles[status];
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-neutral-200 bg-white px-3 py-1 text-sm">
      <span className={`h-2 w-2 rounded-full ${s.dot}`} />
      <span className={s.text}>{s.label}</span>
    </div>
  );
}

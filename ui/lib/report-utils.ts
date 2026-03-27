const SENSITIVE_REPORT_IOC_TYPES = new Set(["username", "password"]);

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  noise: 4,
};

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

function isPrivateCountry(country: any): boolean {
  return String(country?.country_code ?? "").toUpperCase() === "PRIVATE"
    || String(country?.country_name ?? "").toLowerCase() === "private network";
}

function maskUsername(value: string): string {
  if (!value) return value;

  if (value.includes("@")) {
    const [local, domain] = value.split("@", 2);
    if (!domain) return maskUsername(local);
    if (local.length <= 1) return `*@${domain}`;
    if (local.length === 2) return `${local[0]}*@${domain}`;
    return `${local.slice(0, 2)}${"*".repeat(Math.max(local.length - 2, 2))}@${domain}`;
  }

  if (value.length <= 1) return "*";
  if (value.length <= 3) return `${value[0]}${"*".repeat(value.length - 1)}`;
  return `${value.slice(0, 2)}${"*".repeat(Math.max(value.length - 3, 2))}${value.slice(-1)}`;
}

export function maskReportIocValue(iocType: string | null | undefined, value: string | null | undefined): string {
  if (typeof value !== "string") return value ?? "";

  const kind = String(iocType ?? "").toLowerCase();
  if (kind === "password") return "********";
  if (kind === "username") return maskUsername(value);
  return value;
}

export function sanitizeReportIocs(iocs: any[] | null | undefined): any[] {
  if (!Array.isArray(iocs)) return [];

  return iocs.map((ioc) => {
    if (!ioc || typeof ioc !== "object") return ioc;
    const kind = String(ioc.ioc_type ?? "").toLowerCase();
    const isRedacted = SENSITIVE_REPORT_IOC_TYPES.has(kind);
    return {
      ...ioc,
      value: maskReportIocValue(kind, ioc.value),
      is_redacted: isRedacted,
    };
  });
}

export function normalizeReportData(raw: any, fallbackGeneratedAt?: string): any {
  const base = raw && typeof raw === "object" ? raw : {};
  return {
    ...base,
    stats: base.stats ?? {},
    sessions: Array.isArray(base.sessions) ? base.sessions : [],
    attackers: Array.isArray(base.attackers) ? base.attackers : [],
    histogram: Array.isArray(base.histogram) ? base.histogram : [],
    iocs: sanitizeReportIocs(base.iocs),
    generated_at: base.generated_at ?? fallbackGeneratedAt ?? new Date().toISOString(),
  };
}

export function buildReportWindow(rangeHours: number): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to.getTime() - rangeHours * 60 * 60 * 1000);
  return { from: from.toISOString(), to: to.toISOString() };
}

export function buildReportSummary(input: any): {
  totalEvents: number;
  criticalHigh: number;
  cpuStops: number;
  actionableSessions: number;
  externalCountryCount: number;
  hasPrivateCountryTraffic: boolean;
  privateOnlyActivity: boolean;
  credentialIndicatorCount: number;
  redactedIndicatorCount: number;
  modbusWriteIndicatorCount: number;
  s7PayloadIndicatorCount: number;
  topFindings: any[];
  impactSummary: string[];
  recommendations: string[];
} {
  const stats = input?.stats ?? {};
  const sessions = Array.isArray(input?.sessions) ? input.sessions : [];
  const attackers = Array.isArray(input?.attackers) ? input.attackers : [];
  const histogram = Array.isArray(input?.histogram) ? input.histogram : [];
  const iocs = sanitizeReportIocs(input?.iocs);
  const protocols = Array.isArray(stats?.protocols) ? stats.protocols : [];
  const topCountries = Array.isArray(stats?.top_countries) ? stats.top_countries : [];

  const totalEvents = histogram.reduce((sum: number, bucket: any) => sum + Number(bucket?.count ?? 0), 0);
  const criticalHigh = sessions.filter((session: any) => ["critical", "high"].includes(String(session?.severity ?? "").toLowerCase())).length;
  const cpuStops = sessions.filter((session: any) => !!session?.cpu_stop_occurred).length;
  const actionableSessions = sessions.filter((session: any) => !!session?.is_actionable).length;
  const externalCountryCount = topCountries.filter((country: any) => !isPrivateCountry(country)).length;
  const hasPrivateCountryTraffic = topCountries.some((country: any) => isPrivateCountry(country));
  const privateOnlyActivity = attackers.length > 0 && attackers.every((attacker: any) => isPrivateCountry(attacker));

  const credentialIndicatorCount = iocs.filter((ioc: any) =>
    ["username", "password"].includes(String(ioc?.ioc_type ?? "").toLowerCase())
  ).length;
  const redactedIndicatorCount = iocs.filter((ioc: any) => !!ioc?.is_redacted).length;
  const modbusWriteIndicatorCount = iocs.filter((ioc: any) =>
    ["modbus_write_value", "modbus_write_values", "modbus_target"].includes(String(ioc?.ioc_type ?? "").toLowerCase())
  ).length;
  const s7PayloadIndicatorCount = iocs.filter((ioc: any) =>
    String(ioc?.ioc_type ?? "").toLowerCase() === "s7_payload"
  ).length;

  const topFindings = [...sessions]
    .sort((left: any, right: any) => {
      const sevDiff = (SEVERITY_RANK[String(left?.severity ?? "").toLowerCase()] ?? 99)
        - (SEVERITY_RANK[String(right?.severity ?? "").toLowerCase()] ?? 99);
      if (sevDiff !== 0) return sevDiff;
      return Number(right?.event_count ?? 0) - Number(left?.event_count ?? 0);
    })
    .slice(0, 3);

  const impactSummary: string[] = [];
  if (cpuStops > 0) {
    impactSummary.push(
      `${cpuStops} ${pluralize(cpuStops, "session")} included CPU STOP behavior. Validate PLC state and process safety immediately.`
    );
  }
  if (modbusWriteIndicatorCount > 0) {
    impactSummary.push(
      `Modbus write activity surfaced ${modbusWriteIndicatorCount} address or value ${pluralize(modbusWriteIndicatorCount, "indicator")}. Verify coil and register state on affected assets.`
    );
  }
  if (s7PayloadIndicatorCount > 0 && cpuStops === 0) {
    impactSummary.push(
      `S7 write payloads were captured without a confirmed CPU STOP. Review engineering workstation access and recent change windows.`
    );
  }
  if (credentialIndicatorCount > 0) {
    impactSummary.push(
      `${credentialIndicatorCount} credential ${pluralize(credentialIndicatorCount, "indicator")} were captured from HMI activity. Rotate exposed accounts and review jump-host reuse.`
    );
  }
  if (privateOnlyActivity) {
    impactSummary.push(
      "Observed sources were limited to private-network space. Treat this as internal pivoting, test traffic, or a sensor-placement issue until proven otherwise."
    );
  } else if (hasPrivateCountryTraffic) {
    impactSummary.push(
      "This period mixes private and geo-located sources. External country counts exclude private-network traffic by design."
    );
  }
  if (impactSummary.length === 0 && criticalHigh > 0) {
    impactSummary.push(
      `${criticalHigh} high-priority ${pluralize(criticalHigh, "session")} require analyst triage even though destructive writes were not confirmed in this range.`
    );
  }
  if (impactSummary.length === 0 && sessions.length > 0) {
    impactSummary.push(
      "No destructive protocol writes were confirmed in this range. Continue monitoring and correlate with asset telemetry before containment."
    );
  }

  const recommendations: string[] = [];
  const protocolNames: string[] = protocols.map((protocol: any) => String(protocol?.protocol ?? "").toLowerCase());

  if (cpuStops > 0) {
    recommendations.push("Place affected PLCs in a safe state and verify logic/runtime integrity before returning them to production.");
  }
  if (protocolNames.some((protocol) => ["s7comm", "s7"].includes(protocol))) {
    recommendations.push("Restrict S7 PG/PC access to approved engineering stations and segment PLCs behind industrial firewall policy.");
  }
  if (protocolNames.includes("modbus")) {
    recommendations.push("Enforce Modbus read-only baselines and alert on FC05, FC06, FC15, and FC16 write attempts.");
  }
  if (protocolNames.some((protocol) => ["http", "https"].includes(protocol))) {
    recommendations.push("Remove direct internet reachability from HMI endpoints and mediate operator access through hardened jump paths.");
  }
  if (credentialIndicatorCount > 0) {
    recommendations.push("Credential indicators are redacted in this report. Rotate the affected accounts and review password reuse across OT administration paths.");
  }
  if (privateOnlyActivity) {
    recommendations.push("Validate whether the sensor is seeing east-west traffic or NATed sources before using geo metrics for exposure decisions.");
  }
  if (recommendations.length === 0) {
    recommendations.push("Correlate these sessions with historian, firewall, and endpoint telemetry before taking containment actions.");
  }

  return {
    totalEvents,
    criticalHigh,
    cpuStops,
    actionableSessions,
    externalCountryCount,
    hasPrivateCountryTraffic,
    privateOnlyActivity,
    credentialIndicatorCount,
    redactedIndicatorCount,
    modbusWriteIndicatorCount,
    s7PayloadIndicatorCount,
    topFindings,
    impactSummary,
    recommendations: [...new Set(recommendations)].slice(0, 4),
  };
}

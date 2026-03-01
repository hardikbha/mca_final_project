import { useEffect, useState } from "react";
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  LineElement,
  PointElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { Doughnut, Bar, Line } from "react-chartjs-2";
import type { AnalyticsOverview, AnalyticsTrendDay, AnalyticsLatencyStage } from "../../types";
import { fetchAnalyticsOverview, fetchAnalyticsTrends, fetchAnalyticsLatency } from "../../services/api";
import LoadingSkeleton from "../shared/LoadingSkeleton";

ChartJS.register(
  ArcElement, BarElement, LineElement, PointElement,
  CategoryScale, LinearScale,
  Tooltip, Legend, Filler,
);

type Props = { token: string };

const chartFont = { family: "Inter, Manrope, system-ui, sans-serif" } as const;

const tooltipStyle = {
  backgroundColor: "#0f172a",
  titleColor: "#f1f5f9",
  bodyColor: "#94a3b8",
  padding: 12,
  cornerRadius: 8,
  titleFont: { ...chartFont, size: 13, weight: 700 as const },
  bodyFont: { ...chartFont, size: 12 },
  borderColor: "#334155",
  borderWidth: 1,
};

const axisStyle = {
  grid: { color: "rgba(226, 232, 240, 0.8)" },
  ticks: { font: { ...chartFont, size: 11 } as const, color: "#94a3b8" },
  border: { color: "#e2e8f0" },
};

const legendStyle = {
  labels: {
    font: { ...chartFont, size: 12, weight: 600 as const },
    color: "#475569",
    usePointStyle: true,
    pointStyleWidth: 10,
    padding: 16,
  },
};

export default function AnalyticsDashboard({ token }: Props) {
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [trends, setTrends] = useState<AnalyticsTrendDay[]>([]);
  const [latency, setLatency] = useState<AnalyticsLatencyStage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      const [ov, tr, la] = await Promise.all([
        fetchAnalyticsOverview(token),
        fetchAnalyticsTrends(token),
        fetchAnalyticsLatency(token),
      ]);
      if (ov.error && tr.error && la.error) {
        setError("Analytics data unavailable. Ensure you have admin/reviewer access.");
      } else {
        if (ov.data) setOverview(ov.data);
        if (tr.data) setTrends(tr.data.data);
        if (la.data) setLatency(la.data.stages);
      }
      setLoading(false);
    };
    void load();
  }, [token]);

  if (loading) return (
    <div className="analytics-loading">
      <LoadingSkeleton lines={10} />
    </div>
  );

  if (error) return (
    <div className="analytics-error">
      <p>{error}</p>
    </div>
  );

  const recentTrends = trends.slice(-14);

  // Derived KPIs
  const totalSessions = overview?.total_sessions ?? 0;
  const approvedCount = overview?.approved_count ?? 0;
  const rejectedCount = overview?.rejected_count ?? 0;
  const approvalRate = totalSessions > 0
    ? ((approvedCount / totalSessions) * 100).toFixed(1)
    : "—";

  // Labels
  const trendLabels = recentTrends.map(d => {
    const [, m, day] = d.date.split("-");
    return `${m}/${day}`;
  });

  // ── Daily KYC Volume (line + area) ──────────────────────────────
  const volumeData = {
    labels: trendLabels,
    datasets: [
      {
        label: "Approved",
        data: recentTrends.map(d => d.approved),
        backgroundColor: "rgba(16, 185, 129, 0.12)",
        borderColor: "#10b981",
        borderWidth: 2.5,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: "#10b981",
        pointBorderColor: "#fff",
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      },
      {
        label: "Rejected",
        data: recentTrends.map(d => d.rejected),
        backgroundColor: "rgba(244, 63, 94, 0.10)",
        borderColor: "#f43f5e",
        borderWidth: 2.5,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: "#f43f5e",
        pointBorderColor: "#fff",
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      },
      {
        label: "Flagged",
        data: recentTrends.map(d => d.flagged),
        backgroundColor: "rgba(245, 158, 11, 0.10)",
        borderColor: "#f59e0b",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: "#f59e0b",
        pointBorderColor: "#fff",
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      },
    ],
  };

  // ── Daily Approval Rate % (line) ─────────────────────────────────
  const approvalRateData = {
    labels: trendLabels,
    datasets: [
      {
        label: "Approval Rate (%)",
        data: recentTrends.map(d => {
          const total = d.approved + d.rejected + d.flagged;
          return total > 0 ? +((d.approved / total) * 100).toFixed(1) : 0;
        }),
        backgroundColor: "rgba(37, 99, 235, 0.10)",
        borderColor: "#2563eb",
        borderWidth: 2.5,
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: "#2563eb",
        pointBorderColor: "#fff",
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      },
    ],
  };

  // ── KYC Status Doughnut ──────────────────────────────────────────
  const statusData = overview ? {
    labels: ["Approved", "Rejected", "Pending", "Under Review"],
    datasets: [{
      data: [overview.approved_count, overview.rejected_count, overview.pending_count, overview.under_review_count],
      backgroundColor: ["#10b981", "#f43f5e", "#f59e0b", "#6366f1"],
      borderColor: ["#059669", "#e11d48", "#d97706", "#4f46e5"],
      borderWidth: 2,
      hoverOffset: 8,
    }],
  } : null;

  // ── Pipeline Latency (horizontal bar) ────────────────────────────
  const latencyData = {
    labels: latency.map(s =>
      s.stage.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())
    ),
    datasets: [
      {
        label: "Average (ms)",
        data: latency.map(s => s.avg_ms),
        backgroundColor: "rgba(37, 99, 235, 0.85)",
        borderColor: "#2563eb",
        borderWidth: 1,
        borderRadius: 4,
      },
      {
        label: "P95 (ms)",
        data: latency.map(s => s.p95_ms),
        backgroundColor: "rgba(99, 102, 241, 0.55)",
        borderColor: "#6366f1",
        borderWidth: 1,
        borderRadius: 4,
      },
    ],
  };

  return (
    <div className="analytics-container">

      {/* ── KPI Cards ── */}
      {overview && (
        <div className="kpi-grid">
          <div className="kpi-card kpi-blue">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Total Users</span>
              <strong className="kpi-value">{overview.total_users.toLocaleString()}</strong>
            </div>
          </div>

          <div className="kpi-card kpi-emerald">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Approval Rate</span>
              <strong className="kpi-value">{approvalRate}%</strong>
            </div>
          </div>

          <div className="kpi-card kpi-violet">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="3" width="20" height="14" rx="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Total Sessions</span>
              <strong className="kpi-value">{overview.total_sessions.toLocaleString()}</strong>
            </div>
          </div>

          <div className="kpi-card kpi-amber">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Flagged</span>
              <strong className="kpi-value">{overview.flagged_sessions.toLocaleString()}</strong>
            </div>
          </div>

          <div className="kpi-card kpi-rose">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Rejected</span>
              <strong className="kpi-value">{rejectedCount.toLocaleString()}</strong>
            </div>
          </div>

          <div className="kpi-card kpi-slate">
            <div className="kpi-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
            </div>
            <div className="kpi-body">
              <span className="kpi-label">Documents</span>
              <strong className="kpi-value">{overview.total_documents.toLocaleString()}</strong>
            </div>
          </div>
        </div>
      )}

      {/* ── Charts ── */}
      <div className="charts-grid">

        {/* Daily KYC Volume — full width */}
        <div className="chart-card chart-wide">
          <div className="chart-card-header">
            <h3 className="chart-title">Daily KYC Session Volume</h3>
            <p className="chart-subtitle">Approved, rejected and flagged outcomes over the last 14 days</p>
          </div>
          <div className="chart-body chart-lg">
            <Line
              data={volumeData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index" as const, intersect: false },
                plugins: {
                  legend: { ...legendStyle, position: "top" as const },
                  tooltip: tooltipStyle,
                },
                scales: {
                  x: axisStyle,
                  y: { ...axisStyle, min: 0, ticks: { ...axisStyle.ticks, stepSize: 1 } },
                },
              }}
            />
          </div>
        </div>

        {/* KYC Status Distribution */}
        {statusData && (
          <div className="chart-card">
            <div className="chart-card-header">
              <h3 className="chart-title">KYC Status Distribution</h3>
              <p className="chart-subtitle">All-time breakdown — {totalSessions} total sessions</p>
            </div>
            <div className="chart-body chart-md">
              <Doughnut
                data={statusData}
                options={{
                  responsive: true,
                  maintainAspectRatio: false,
                  cutout: "64%",
                  plugins: {
                    legend: { ...legendStyle, position: "bottom" as const },
                    tooltip: tooltipStyle,
                  },
                }}
              />
            </div>
          </div>
        )}

        {/* Daily Approval Rate % */}
        <div className="chart-card">
          <div className="chart-card-header">
            <h3 className="chart-title">Daily Approval Rate</h3>
            <p className="chart-subtitle">Percentage of sessions approved per day</p>
          </div>
          <div className="chart-body chart-md">
            <Line
              data={approvalRateData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index" as const, intersect: false },
                plugins: {
                  legend: { display: false },
                  tooltip: {
                    ...tooltipStyle,
                    callbacks: { label: (ctx) => ` ${ctx.parsed.y}%` },
                  },
                },
                scales: {
                  x: axisStyle,
                  y: {
                    ...axisStyle,
                    min: 0,
                    max: 100,
                    ticks: {
                      ...axisStyle.ticks,
                      callback: (val: string | number) => `${val}%`,
                    },
                  },
                },
              }}
            />
          </div>
        </div>

        {/* Pipeline Stage Latency — full width */}
        <div className="chart-card chart-wide">
          <div className="chart-card-header">
            <h3 className="chart-title">Pipeline Stage Latency</h3>
            <p className="chart-subtitle">Average and P95 response times per stage (milliseconds)</p>
          </div>
          <div className="chart-body chart-md">
            <Bar
              data={latencyData}
              options={{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y" as const,
                interaction: { mode: "index" as const, intersect: false },
                plugins: {
                  legend: { ...legendStyle, position: "top" as const },
                  tooltip: {
                    ...tooltipStyle,
                    callbacks: { label: (ctx) => ` ${(ctx.parsed.x ?? 0).toLocaleString()} ms` },
                  },
                },
                scales: {
                  x: {
                    ...axisStyle,
                    ticks: {
                      ...axisStyle.ticks,
                      callback: (val: string | number) => `${Number(val).toLocaleString()}ms`,
                    },
                  },
                  y: axisStyle,
                },
              }}
            />
          </div>
        </div>

      </div>
    </div>
  );
}

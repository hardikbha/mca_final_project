import { useEffect, useState } from "react";
import { Chart as ChartJS, ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend } from "chart.js";
import { Doughnut, Bar } from "react-chartjs-2";
import type { AnalyticsOverview, AnalyticsTrendDay, AnalyticsLatencyStage } from "../../types";
import { fetchAnalyticsOverview, fetchAnalyticsTrends, fetchAnalyticsLatency } from "../../services/api";
import LoadingSkeleton from "../shared/LoadingSkeleton";

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend);

type Props = { token: string };

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

  if (loading) return <section className="content-grid"><article className="panel"><LoadingSkeleton lines={8} /></article></section>;
  if (error) return <section className="content-grid"><article className="panel"><p>{error}</p></article></section>;

  const statusData = overview ? {
    labels: ["Approved", "Rejected", "Pending", "Under Review"],
    datasets: [{
      data: [overview.approved_count, overview.rejected_count, overview.pending_count, overview.under_review_count],
      backgroundColor: ["#22c55e", "#ef4444", "#f59e0b", "#3b82f6"],
    }],
  } : null;

  // Show last 14 days for readability
  const recentTrends = trends.slice(-14);
  const trendData = {
    labels: recentTrends.map((d) => d.date.slice(5)),
    datasets: [
      { label: "Approved", data: recentTrends.map((d) => d.approved), backgroundColor: "#22c55e" },
      { label: "Rejected", data: recentTrends.map((d) => d.rejected), backgroundColor: "#ef4444" },
      { label: "Flagged", data: recentTrends.map((d) => d.flagged), backgroundColor: "#f59e0b" },
    ],
  };

  const latencyData = {
    labels: latency.map((s) => s.stage.replace(/_/g, " ")),
    datasets: [
      { label: "Avg (ms)", data: latency.map((s) => s.avg_ms), backgroundColor: "#3b82f6" },
      { label: "P95 (ms)", data: latency.map((s) => s.p95_ms), backgroundColor: "#93c5fd" },
    ],
  };

  return (
    <section className="analytics-grid">
      {overview && (
        <article className="panel glass analytics-stats">
          <h2>System Overview</h2>
          <div className="score-grid">
            <div className="score-box"><span>Total Users</span><strong>{overview.total_users}</strong></div>
            <div className="score-box"><span>Total Documents</span><strong>{overview.total_documents}</strong></div>
            <div className="score-box"><span>Total Sessions</span><strong>{overview.total_sessions}</strong></div>
            <div className="score-box"><span>Flagged</span><strong>{overview.flagged_sessions}</strong></div>
          </div>
        </article>
      )}

      {statusData && (
        <article className="panel glass analytics-chart">
          <h2>KYC Status Distribution</h2>
          <div className="chart-wrapper chart-doughnut">
            <Doughnut data={statusData} options={{ responsive: true, maintainAspectRatio: true }} />
          </div>
        </article>
      )}

      <article className="panel glass analytics-chart">
        <h2>Daily Trends (Last 14 Days)</h2>
        <div className="chart-wrapper">
          <Bar data={trendData} options={{ responsive: true, scales: { x: { stacked: true }, y: { stacked: true } } }} />
        </div>
      </article>

      <article className="panel glass analytics-chart">
        <h2>Average Latency per Stage</h2>
        <div className="chart-wrapper">
          <Bar data={latencyData} options={{ responsive: true, indexAxis: "y" as const }} />
        </div>
      </article>
    </section>
  );
}

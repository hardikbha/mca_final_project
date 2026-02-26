import type { TabKey } from "../../types";

type TabDef = { key: TabKey; label: string; subtitle: string };

const TABS: TabDef[] = [
  { key: "overview", label: "Overview", subtitle: "See all scores and pipeline status" },
  { key: "ocr", label: "Document OCR", subtitle: "Upload PDF/PNG/JPG and detect forgery risk" },
  { key: "face", label: "Face Match", subtitle: "Compare document face with live/uploaded face" },
  { key: "deepfake", label: "Deepfake", subtitle: "Analyze current shared image for deepfake risk" },
  { key: "liveness", label: "Liveness", subtitle: "Single image liveness confidence check" },
  { key: "final", label: "Final Report", subtitle: "Combine all four scores and generate PDF" },
  { key: "analytics", label: "Analytics", subtitle: "Dashboard with trends and metrics" },
];

type Props = {
  activeTab: TabKey;
  onTabChange: (tab: TabKey) => void;
  showAnalytics: boolean;
};

export default function Taskbar({ activeTab, onTabChange, showAnalytics }: Props) {
  const visibleTabs = showAnalytics ? TABS : TABS.filter((t) => t.key !== "analytics");

  return (
    <nav className="taskbar">
      {visibleTabs.map((tab) => (
        <button
          key={tab.key}
          onClick={() => onTabChange(tab.key)}
          className={tab.key === activeTab ? "task active" : "task"}
        >
          <span>{tab.label}</span>
          <small>{tab.subtitle}</small>
        </button>
      ))}
    </nav>
  );
}

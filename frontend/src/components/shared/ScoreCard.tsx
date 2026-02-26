type Props = {
  label: string;
  value: number | null;
  threshold?: number;
  invert?: boolean;
  isFinal?: boolean;
};

export default function ScoreCard({ label, value, threshold, invert = false, isFinal = false }: Props) {
  let colorClass = "";
  if (value !== null && threshold !== undefined) {
    const passing = invert ? value <= threshold : value >= threshold;
    colorClass = passing ? "score-pass" : "score-fail";
  }

  return (
    <div className={`score-box ${isFinal ? "final" : ""} ${colorClass}`}>
      <span>{label}</span>
      <strong>{value !== null ? value.toFixed(2) : "—"}</strong>
    </div>
  );
}

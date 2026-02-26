type Props = {
  lines?: number;
  widths?: string[];
};

export default function LoadingSkeleton({ lines = 4, widths }: Props) {
  const defaultWidths = ["100%", "85%", "92%", "60%", "75%", "88%"];
  return (
    <div className="skeleton-container">
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="skeleton-line"
          style={{ width: widths?.[i] ?? defaultWidths[i % defaultWidths.length] }}
        />
      ))}
    </div>
  );
}

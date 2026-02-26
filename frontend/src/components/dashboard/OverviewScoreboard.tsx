import type { DocumentResult, FaceMatchResult, DeepfakeResult, LivenessResult, FinalReportResult } from "../../types";
import ScoreCard from "../shared/ScoreCard";

type Props = {
  documentResult: DocumentResult | null;
  faceResult: FaceMatchResult | null;
  deepfakeResult: DeepfakeResult | null;
  livenessResult: LivenessResult | null;
  finalResult: FinalReportResult | null;
};

export default function OverviewScoreboard({ documentResult, faceResult, deepfakeResult, livenessResult, finalResult }: Props) {
  return (
    <section className="scoreboard-bar">
      <ScoreCard label="Doc Forgery" value={documentResult?.document_forgery_score ?? null} threshold={30} invert />
      <ScoreCard label="Face Match" value={faceResult?.face_match_score ?? null} threshold={80} />
      <ScoreCard label="Deepfake" value={deepfakeResult?.deepfake_score ?? null} threshold={30} invert />
      <ScoreCard label="Liveness" value={livenessResult?.liveness_score ?? null} threshold={60} />
      <ScoreCard label="Final" value={finalResult?.scores.final_score ?? null} isFinal />
    </section>
  );
}

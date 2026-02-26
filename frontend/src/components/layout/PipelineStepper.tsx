type Step = {
  number: number;
  label: string;
  done: boolean;
};

type Props = {
  steps: Step[];
};

export default function PipelineStepper({ steps }: Props) {
  return (
    <div className="pipeline-stepper">
      {steps.map((step, i) => (
        <div key={step.number} className="stepper-item-wrap">
          <div className={`stepper-item ${step.done ? "stepper-done" : ""}`}>
            <div className="stepper-circle">{step.done ? "\u2713" : step.number}</div>
            <span className="stepper-label">{step.label}</span>
          </div>
          {i < steps.length - 1 && (
            <div className={`stepper-line ${step.done ? "stepper-line-done" : ""}`} />
          )}
        </div>
      ))}
    </div>
  );
}

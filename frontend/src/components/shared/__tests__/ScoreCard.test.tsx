import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import ScoreCard from "../ScoreCard";

describe("ScoreCard", () => {
  it("renders label and value", () => {
    render(<ScoreCard label="Face Match" value={85.5} />);
    expect(screen.getByText("Face Match")).toBeTruthy();
    expect(screen.getByText("85.50")).toBeTruthy();
  });

  it("shows dash when value is null", () => {
    render(<ScoreCard label="Liveness" value={null} />);
    expect(screen.getByText("—")).toBeTruthy();
  });

  it("applies pass class when above threshold", () => {
    const { container } = render(<ScoreCard label="Match" value={90} threshold={80} />);
    expect(container.querySelector(".score-pass")).toBeTruthy();
  });

  it("applies fail class when below threshold", () => {
    const { container } = render(<ScoreCard label="Match" value={50} threshold={80} />);
    expect(container.querySelector(".score-fail")).toBeTruthy();
  });

  it("inverts threshold logic for risk scores", () => {
    const { container } = render(<ScoreCard label="Deepfake" value={20} threshold={30} invert />);
    expect(container.querySelector(".score-pass")).toBeTruthy();
  });
});

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ToastProvider, useToast } from "../../../contexts/ToastContext";
import { useEffect } from "react";

function ToastTrigger({ message, type }: { message: string; type: "success" | "error" }) {
  const { showToast } = useToast();
  useEffect(() => { showToast(message, type); }, [message, type, showToast]);
  return null;
}

describe("Toast", () => {
  it("renders a toast message", () => {
    render(
      <ToastProvider>
        <ToastTrigger message="Operation done" type="success" />
      </ToastProvider>
    );
    expect(screen.getByText("Operation done")).toBeTruthy();
  });

  it("has correct type class", () => {
    const { container } = render(
      <ToastProvider>
        <ToastTrigger message="Error occurred" type="error" />
      </ToastProvider>
    );
    expect(container.querySelector(".toast-error")).toBeTruthy();
  });
});

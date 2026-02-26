import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import LoginForm from "../LoginForm";

describe("LoginForm", () => {
  it("renders login form fields", () => {
    render(<LoginForm onLogin={vi.fn()} isBusy={false} />);
    expect(screen.getByRole("heading", { name: "Login" })).toBeTruthy();
    expect(screen.getByText("Login ID")).toBeTruthy();
    expect(screen.getByText("Password")).toBeTruthy();
  });

  it("shows validation error for short identifier", () => {
    render(<LoginForm onLogin={vi.fn()} isBusy={false} />);
    const inputs = screen.getAllByRole("textbox");
    fireEvent.change(inputs[0], { target: { value: "ab" } });
    fireEvent.click(screen.getByRole("button", { name: "Login" }));
    expect(screen.getByText("Min 3 characters.")).toBeTruthy();
  });

  it("disables button when busy", () => {
    render(<LoginForm onLogin={vi.fn()} isBusy={true} />);
    const button = screen.getByText("Please wait...");
    expect((button as HTMLButtonElement).disabled).toBe(true);
  });
});

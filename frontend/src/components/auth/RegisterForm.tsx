import { useState } from "react";

type Props = {
  onRegister: (data: { full_name: string; email: string; phone: string; password: string }) => Promise<void>;
  isBusy: boolean;
};

const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export default function RegisterForm({ onRegister, isBusy }: Props) {
  const [form, setForm] = useState({ full_name: "", email: "", phone: "", password: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const e: Record<string, string> = {};
    if (!form.full_name.trim()) e.full_name = "Name is required.";
    if (!emailRegex.test(form.email)) e.email = "Valid email required.";
    if (!/^\d{10}$/.test(form.phone)) e.phone = "10-digit phone required.";
    if (form.password.length < 6) e.password = "Min 6 characters.";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = () => {
    if (validate()) void onRegister(form);
  };

  return (
    <article className="panel glass">
      <h2>Register</h2>
      <label>
        Full Name
        <input
          value={form.full_name}
          onChange={(e) => setForm((p) => ({ ...p, full_name: e.target.value }))}
          className={errors.full_name ? "input-error" : ""}
        />
        {errors.full_name && <small className="field-error">{errors.full_name}</small>}
      </label>
      <label>
        Email
        <input
          value={form.email}
          onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))}
          className={errors.email ? "input-error" : ""}
        />
        {errors.email && <small className="field-error">{errors.email}</small>}
      </label>
      <label>
        Phone
        <input
          value={form.phone}
          onChange={(e) => setForm((p) => ({ ...p, phone: e.target.value }))}
          className={errors.phone ? "input-error" : ""}
        />
        {errors.phone && <small className="field-error">{errors.phone}</small>}
      </label>
      <label>
        Password
        <input
          type="password"
          value={form.password}
          onChange={(e) => setForm((p) => ({ ...p, password: e.target.value }))}
          className={errors.password ? "input-error" : ""}
        />
        {errors.password && <small className="field-error">{errors.password}</small>}
      </label>
      <button onClick={handleSubmit} className="btn secondary" disabled={isBusy}>
        {isBusy ? "Please wait..." : "Register"}
      </button>
    </article>
  );
}

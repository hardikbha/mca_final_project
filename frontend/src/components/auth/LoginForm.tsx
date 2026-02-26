import { useState } from "react";

type Props = {
  onLogin: (identifier: string, password: string) => Promise<void>;
  isBusy: boolean;
};

export default function LoginForm({ onLogin, isBusy }: Props) {
  const [form, setForm] = useState({ identifier: "", password: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const e: Record<string, string> = {};
    if (form.identifier.trim().length < 3) e.identifier = "Min 3 characters.";
    if (form.password.length < 4) e.password = "Min 4 characters.";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleSubmit = () => {
    if (validate()) void onLogin(form.identifier, form.password);
  };

  return (
    <article className="panel glass">
      <h2>Login</h2>
      <label>
        Login ID
        <input
          value={form.identifier}
          onChange={(e) => setForm((p) => ({ ...p, identifier: e.target.value }))}
          className={errors.identifier ? "input-error" : ""}
        />
        {errors.identifier && <small className="field-error">{errors.identifier}</small>}
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
      <button onClick={handleSubmit} className="btn primary" disabled={isBusy}>
        {isBusy ? "Please wait..." : "Login"}
      </button>
    </article>
  );
}

import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useNavigate } from "@tanstack/react-router";
export default function LoginPage() {
  const { login } = useAuth();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await login(form);
      navigate({ to: "/dash" });
    } catch (err) {
      console.error("Login failed", err);
      setError("Login failed");
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={form.username}
        onChange={(e) => setForm({ ...form, username: e.target.value })}
      />
      <input
        type="password"
        value={form.password}
        onChange={(e) => setForm({ ...form, password: e.target.value })}
      />
      <button type="submit">Login</button>
      {error && <div>{error}</div>}
    </form>
  );
}

import { createFileRoute, useNavigate } from "@tanstack/react-router";
import LoginPage from "../components/LoginPage";
import { useAuth } from "../context/AuthContext";

export const Route = createFileRoute("/login")({
  component: RouteComponent,
});

function RouteComponent() {
  const { user } = useAuth();
  const navigate = useNavigate();
  if (user) {
    navigate({ to: "/dash" });
  }
  return <LoginPage />;
}

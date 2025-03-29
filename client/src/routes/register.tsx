import { createFileRoute, useNavigate } from "@tanstack/react-router";
import RegisterPage from "../components/RegisterPage";
import { useAuth } from "../context/AuthContext";
export const Route = createFileRoute("/register")({
  component: RouteComponent,
});

function RouteComponent() {
  const { user } = useAuth();
  const navigate = useNavigate();
  if (user) {
    navigate({ to: "/dash" });
  }
  return <RegisterPage />;
}

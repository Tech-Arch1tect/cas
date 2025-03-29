import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useAuth } from "../context/AuthContext";

export const Route = createFileRoute("/dash")({
  component: RouteComponent,
});

function RouteComponent() {
  const { user } = useAuth();
  const navigate = useNavigate();
  if (!user) {
    navigate({ to: "/login" });
  }
  return <div>Hello "/dash"!</div>;
}

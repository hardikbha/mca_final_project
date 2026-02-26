import type { UserInfo } from "../../types";

type Props = {
  user: UserInfo | null;
  onLogout: () => void;
};

export default function WorkspaceHeader({ user, onLogout }: Props) {
  return (
    <header className="workspace-header">
      <div>
        <p className="eyebrow">eKYC Verification Workbench</p>
        <h1>AI-based Real-Time eKYC System</h1>
        <p className="subtext">
          Logged in as <strong>{user?.full_name ?? "User"}</strong>
          {user?.role && <span className="role-badge"> ({user.role})</span>}
        </p>
      </div>
      <button onClick={onLogout} className="btn danger">Logout</button>
    </header>
  );
}

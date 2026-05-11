import packageJson from "../package.json";

import { CommandCenterShell } from "@/components/command-center-shell";

export default function Home() {
  const appVersion = process.env.NEXT_PUBLIC_APP_VERSION?.trim() || packageJson.version;

  return <CommandCenterShell appVersion={appVersion} />;
}
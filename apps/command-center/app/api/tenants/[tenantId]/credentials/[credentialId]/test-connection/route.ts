import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  context: { params: Promise<{ tenantId: string; credentialId: string }> },
) {
  const { tenantId, credentialId } = await context.params;
  return proxyControlPlaneJson(
    `/v1/tenants/${tenantId}/credentials/${credentialId}/test-connection`,
    { method: "POST", body: {}, incomingRequest: request },
  );
}

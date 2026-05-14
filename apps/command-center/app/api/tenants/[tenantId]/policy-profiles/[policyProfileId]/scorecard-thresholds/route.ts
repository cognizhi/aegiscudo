import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string; policyProfileId: string }> },
) {
  const { tenantId, policyProfileId } = await context.params;
  if (!UUID_RE.test(tenantId) || !UUID_RE.test(policyProfileId)) {
    return Response.json({ message: "Invalid path parameter" }, { status: 400 });
  }
  return proxyControlPlaneJson(
    `/v1/tenants/${tenantId}/policy-profiles/${policyProfileId}/scorecard-thresholds`,
    { incomingRequest: request },
  );
}

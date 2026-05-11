import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/llm-usage`, { incomingRequest: request });
}
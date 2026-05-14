import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  const search = new URL(request.url).search;
  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/openvex-documents${search}`, {
    incomingRequest: request,
  });
}
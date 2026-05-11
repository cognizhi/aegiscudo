import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  const url = new URL(request.url);
  const upstream = new URL(`/v1/tenants/${tenantId}/audit-events/export.csv`, "http://placeholder");
  for (const [key, value] of url.searchParams.entries()) {
    upstream.searchParams.set(key, value);
  }

  return proxyControlPlaneJson(`${upstream.pathname}${upstream.search}`, {
    incomingRequest: request,
  });
}
import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  const url = new URL(request.url);
  const action = url.searchParams.get("action");
  const actor = url.searchParams.get("actor");
  const limit = url.searchParams.get("limit");

  const upstream = new URL(`/v1/tenants/${tenantId}/audit-events`, "http://placeholder");
  if (action) upstream.searchParams.set("action", action);
  if (actor) upstream.searchParams.set("actor", actor);
  if (limit) upstream.searchParams.set("limit", limit);

  return proxyControlPlaneJson(`${upstream.pathname}${upstream.search}`, { incomingRequest: request });
}

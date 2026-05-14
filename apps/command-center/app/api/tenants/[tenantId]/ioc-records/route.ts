import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  if (!UUID_RE.test(tenantId)) {
    return Response.json({ message: "Invalid path parameter" }, { status: 400 });
  }
  const { searchParams } = new URL(request.url);
  const allowed = new URLSearchParams();
  const limit = searchParams.get("limit");
  const indicatorType = searchParams.get("indicator_type");
  if (limit != null) allowed.set("limit", limit);
  if (indicatorType != null) allowed.set("indicator_type", indicatorType);
  const qs = allowed.size > 0 ? `?${allowed.toString()}` : "";
  return proxyControlPlaneJson(
    `/v1/tenants/${tenantId}/ioc-records${qs}`,
    { incomingRequest: request },
  );
}

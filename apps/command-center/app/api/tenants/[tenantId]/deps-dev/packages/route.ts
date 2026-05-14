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
  const qs = searchParams.size > 0 ? `?${searchParams.toString()}` : "";
  return proxyControlPlaneJson(
    `/v1/tenants/${tenantId}/deps-dev/packages${qs}`,
    { incomingRequest: request },
  );
}

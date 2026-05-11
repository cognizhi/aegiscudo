import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/credentials`, { incomingRequest: request });
}

export async function POST(
  request: Request,
  context: { params: Promise<{ tenantId: string }> },
) {
  const { tenantId } = await context.params;
  const body = await request.json().catch(() => null);

  if (!body || typeof body !== "object") {
    return Response.json({ message: "Invalid JSON body" }, { status: 400 });
  }

  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/credentials`, {
    method: "POST",
    body,
    incomingRequest: request,
  });
}

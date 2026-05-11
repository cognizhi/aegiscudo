import { proxyControlPlaneJson } from "@/lib/control-plane";

export const dynamic = "force-dynamic";

export async function PATCH(
  request: Request,
  context: { params: Promise<{ tenantId: string; credentialId: string }> },
) {
  const { tenantId, credentialId } = await context.params;
  const body = await request.json().catch(() => null);

  if (!body || typeof body !== "object") {
    return Response.json({ message: "Invalid JSON body" }, { status: 400 });
  }

  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/credentials/${credentialId}`, {
    method: "PATCH",
    body,
    incomingRequest: request,
  });
}

export async function DELETE(
  request: Request,
  context: { params: Promise<{ tenantId: string; credentialId: string }> },
) {
  const { tenantId, credentialId } = await context.params;
  return proxyControlPlaneJson(`/v1/tenants/${tenantId}/credentials/${credentialId}`, {
    method: "DELETE",
    incomingRequest: request,
  });
}

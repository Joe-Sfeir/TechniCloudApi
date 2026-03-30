import type { Response } from 'express';

// Use globalThis to guarantee a single shared Map regardless of how ts-node ESM
// resolves the module — duplicate specifier resolution creates two module instances
// each with their own Map, causing addClient and broadcast to see different state.
const GLOBAL_KEY = '__technidaq_sse_clients__' as const;

function getClients(): Map<number, Set<Response>> {
  if (!(globalThis as Record<string, unknown>)[GLOBAL_KEY]) {
    (globalThis as Record<string, unknown>)[GLOBAL_KEY] = new Map<number, Set<Response>>();
  }
  return (globalThis as Record<string, unknown>)[GLOBAL_KEY] as Map<number, Set<Response>>;
}

export function addClient(projectId: number, res: Response): void {
  const clients = getClients();
  if (!clients.has(projectId)) clients.set(projectId, new Set());
  clients.get(projectId)!.add(res);
}

export function removeClient(projectId: number, res: Response): void {
  getClients().get(projectId)?.delete(res);
}

export function broadcast(projectId: number, eventType: string, data: unknown): void {
  console.log('[sse-debug] broadcast called, projectId=', projectId, 'clients=', getClients().get(projectId)?.size ?? 0);
  const clients = getClients();
  const projectClients = clients.get(projectId);
  if (!projectClients || projectClients.size === 0) return;
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  let count = 0;
  for (const res of projectClients) {
    try {
      res.write(payload);
      count++;
    } catch {
      removeClient(projectId, res);
    }
  }
  console.log(`[sse] broadcast project=${projectId} event=${eventType} clients=${count}`);
}

export function getClientCount(projectId: number): number {
  return getClients().get(projectId)?.size ?? 0;
}

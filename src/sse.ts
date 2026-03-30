import type { Response } from 'express';

const clients = new Map<number, Set<Response>>();

export function addClient(projectId: number, res: Response): void {
  if (!clients.has(projectId)) clients.set(projectId, new Set());
  clients.get(projectId)!.add(res);
}

export function removeClient(projectId: number, res: Response): void {
  clients.get(projectId)?.delete(res);
}

export function broadcast(projectId: number, eventType: string, data: unknown): void {
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
  return clients.get(projectId)?.size ?? 0;
}

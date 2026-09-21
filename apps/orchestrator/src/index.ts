import type { Env } from './types';
import { handleCommanderRequest } from './commander/api';
import { handleAnalysisBatch } from './commander/queue-consumer';
import { handleShieldRequest } from './shield';

export type { Env } from './types';
export { IncidentCommander } from './commander/incident-commander';
export { CampaignTracker } from './commander/campaign-tracker';

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        const commanderResponse = await handleCommanderRequest(request, env);
        if (commanderResponse) return commanderResponse;
        // `ctx` lets the Shield report its own blocks after the response is sent.
        return handleShieldRequest(request, env, fetch, ctx);
    },
    async queue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
        await handleAnalysisBatch(batch, env);
    },
};

export const PROBE_PATTERNS = [
  /^(hi|hello|hey|helo)$/i, /^(can you see this|do you see this|did you get this)/i,
  /^(is this \w+|are you \w+)/i, /^(testing|test)/i, /^\?+$/, /^(yes|no|ok|okay)$/i,
];

export function isPotentialProbe(text: string): boolean {
  const trimmed = text.trim().toLowerCase();
  if (trimmed.length < 15) { return PROBE_PATTERNS.some(pattern => pattern.test(trimmed)); }
  return false;
}

export function isScamFollowup(text: string): boolean {
  const hasUrgency = /(urgent|immediate|now|today|asap|quickly)/i.test(text);
  const hasSensitiveRequest = /(otp|pin|cvv|password|account|card|upi)/i.test(text);
  return hasUrgency && hasSensitiveRequest;
}

export async function checkProbePattern(sessionId: string, currentMessage: string, supabase: any): Promise<{ isProbe: boolean; probeConfirmed: boolean; shouldActivateHoneypot: boolean }> {
  const { data: session } = await supabase.from('sessions').select('*').eq('session_id', sessionId).single();
  const { data: messages } = await supabase.from('messages').select('id').eq('session_id', sessionId);
  const messageCount = messages?.length || 0;
  if (messageCount <= 1) {
    const isProbe = isPotentialProbe(currentMessage);
    if (isProbe) {
      await supabase.from('sessions').update({ is_potential_probe: true, probe_detected_at: new Date().toISOString() }).eq('session_id', sessionId);
      return { isProbe: true, probeConfirmed: false, shouldActivateHoneypot: false };
    }
  }
  if (session?.is_potential_probe && !session?.probe_confirmed) {
    if (isScamFollowup(currentMessage)) {
      await supabase.from('sessions').update({ probe_confirmed: true, scam_detected: true, scam_confirmed: true, agent_activated: true }).eq('session_id', sessionId);
      return { isProbe: false, probeConfirmed: true, shouldActivateHoneypot: true };
    }
  }
  return { isProbe: false, probeConfirmed: false, shouldActivateHoneypot: false };
}

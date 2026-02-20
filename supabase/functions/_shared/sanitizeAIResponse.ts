export function sanitizeAIResponse(text: string): string {
  let sanitized = text;
  sanitized = sanitized.replace(/\b\d{16}\b/g, '****');
  const potentialAccounts = sanitized.match(/\b\d{9,18}\b/g) || [];
  potentialAccounts.forEach(num => {
    if (/^(17|18|19|20)/.test(num)) return;
    const uniqueDigits = new Set(num.split('')).size;
    if (uniqueDigits >= 5) { sanitized = sanitized.replace(num, 'wait where do i find that??'); }
  });
  const upiPattern = /\b[a-zA-Z0-9._-]+@(ybl|paytm|oksbi|okaxis|okicici|okhdfcbank|waicici|airtel|fbl|ibl)\b/gi;
  const upiMatches = sanitized.match(upiPattern) || [];
  upiMatches.forEach(upi => {
    const username = upi.split('@')[0];
    if (username.length > 5 && !/^(test|demo|fake|sample)/.test(username.toLowerCase())) {
      sanitized = sanitized.replace(upi, 'umm i think its something@...');
    }
  });
  sanitized = sanitized.replace(/\b[A-Z]{4}0[A-Z0-9]{6}\b/g, '****');
  const phonePattern = /(?:\+?91[-\s]?)?[6-9]\d{9}\b/g;
  const phones = sanitized.match(phonePattern) || [];
  phones.forEach(phone => {
    const context = sanitized.toLowerCase();
    if (context.includes('my number') || context.includes('my phone')) {
      sanitized = sanitized.replace(phone, 'let me check...');
    }
  });
  return sanitized;
}

export function sanitizeAndLog(text: string, sessionId: string): { sanitized: string; wasSanitized: boolean } {
  const sanitized = sanitizeAIResponse(text);
  const wasSanitized = text !== sanitized;
  if (wasSanitized) {
    console.warn('AI response sanitized:', { sessionId, original: text, sanitized,
      removedPatterns: { hadCardNumber: /\b\d{16}\b/.test(text), hadUPI: /@(ybl|paytm)/i.test(text), hadIFSC: /[A-Z]{4}0[A-Z0-9]{6}/.test(text) },
    });
  }
  return { sanitized, wasSanitized };
}

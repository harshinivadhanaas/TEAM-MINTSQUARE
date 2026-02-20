import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { sanitizeAndLog } from "../_shared/sanitizeAIResponse.ts";
import { checkProbePattern } from "../_shared/detectProbe.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-api-key, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// ==================== CONNECTION POOLING: Singleton Supabase client ====================
let _supabase: ReturnType<typeof createClient> | null = null;
function getSupabaseClient() {
  if (!_supabase) {
    _supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
      { db: { schema: "public" }, global: { headers: {} } }
    );
  }
  return _supabase;
}

// ==================== CACHING LAYER ====================
interface CacheEntry<T> { value: T; expiresAt: number; }

class MemoryCache<T> {
  private store = new Map<string, CacheEntry<T>>();
  private ttlMs: number;

  constructor(ttlSeconds: number) {
    this.ttlMs = ttlSeconds * 1000;
  }

  get(key: string): T | null {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  set(key: string, value: T) {
    if (this.store.size > 500) {
      const now = Date.now();
      for (const [k, v] of this.store) {
        if (now > v.expiresAt) this.store.delete(k);
      }
      if (this.store.size > 400) {
        const keys = [...this.store.keys()].slice(0, 100);
        keys.forEach(k => this.store.delete(k));
      }
    }
    this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  invalidate(key: string) { this.store.delete(key); }
}

const apiKeyCache = new MemoryCache<{ id: string; is_active: boolean }>(300);
const sessionCache = new MemoryCache<any>(30);
const detectionCache = new MemoryCache<any>(60);

// ==================== EXPANDED KEYWORD DATABASE ====================
const SCAM_KEYWORDS = {
  account: ["blocked", "suspended", "frozen", "locked", "deactivated", "restricted", "compromised", "unauthorized", "flagged", "disabled", "closed", "terminated"],
  urgency: ["immediately", "urgent", "now", "today", "within", "expire", "deadline", "quickly", "hurry", "asap", "right away", "last chance", "final notice", "2 hours", "24 hours", "expires", "time limit", "running out"],
  financial: ["verify", "confirm", "update", "kyc", "pan", "aadhaar", "aadhar", "identity", "authenticate", "validate", "reactivate", "re-verify"],
  sensitive: ["otp", "pin", "cvv", "password", "card number", "account number", "secret", "code", "credentials", "login details", "security code", "mpin", "atm pin", "net banking"],
  rewards: ["won", "prize", "lottery", "refund", "cashback", "reward", "bonus", "congratulations", "winner", "lucky", "selected", "claim", "gift card", "voucher", "free", "offer"],
  authority: ["bank", "rbi", "government", "tax department", "police", "sbi", "hdfc", "icici", "income tax", "customs", "cyber cell", "reserve bank", "ministry", "irs", "federal", "axis bank", "pnb", "bob", "canara"],
  payment: ["send money", "transfer", "pay", "deposit", "processing fee", "registration fee", "advance", "down payment", "₹", "rupees", "rs", "inr"],
  threat: ["arrest", "legal action", "warrant", "court", "case filed", "investigation", "prosecution", "jail", "penalty", "fine", "seized"],
  social: ["dear customer", "dear sir", "dear madam", "valued customer", "account holder", "respected"],
  tech_support: ["virus", "malware", "expired", "subscription", "license", "microsoft", "apple", "google", "tech support", "remote access", "teamviewer", "anydesk"],
  investment: ["guaranteed returns", "double your money", "invest", "trading", "profit", "crypto", "bitcoin", "forex", "stock tip", "high returns", "risk free"],
};

const SCAM_PATTERNS = {
  otpRequest: /\b(send|share|enter|provide|give|tell|forward).{0,30}(otp|pin|cvv|password|code|mpin)\b/i,
  sensitiveRequest: /\b(otp|cvv|pin|password|card.?details|account.?number|mpin|net.?banking|credentials)\b/i,
  urlWithUrgency: /(https?:\/\/[^\s]+).{0,80}(urgent|immediately|now|verify|confirm|expire|block|suspend)/i,
  upiRequest: /\b(upi|gpay|paytm|phonepe|google.?pay|amazon.?pay).{0,30}(id|send|transfer|pay|number)\b/i,
  downloadApp: /\b(download|install|click|open|visit|tap).{0,30}(app|apk|link|url|website)\b/i,
  prizeWithPayment: /\b(won|prize|lottery|winner|selected|claim).{0,80}(pay|send|transfer|fee|charge|deposit|processing)\b/i,
  impersonation: /\b(this is|calling from|representative of|behalf of|from the|i am from).{0,30}(bank|sbi|hdfc|rbi|government|police|tax|customs|icici|axis)\b/i,
  accountThreat: /\b(account|card|access|service|number).{0,30}(block|suspend|freeze|close|deactivate|terminate|disable|restrict|flag)\b/i,
  moneyRequest: /\b(send|transfer|pay|deposit)\s+(₹|rs\.?|inr|rupees?)?\s*\d+/i,
  linkInMessage: /https?:\/\/[^\s<>"']+/i,
  phoneInMessage: /(?:\+?91[-\s]?)?[6-9]\d{9}/,
  kycRequest: /\b(kyc|pan|aadhaar|aadhar).{0,30}(update|verify|confirm|submit|upload|share|required|pending|expired)\b/i,
  refundScam: /\b(refund|cashback|compensation|claim).{0,30}(process|credit|pending|approve|receive)\b/i,
  clickLink: /\b(click|tap|visit|open|go to).{0,20}(link|url|below|here|this)\b/i,
};

const BANK_ACCOUNT_REGEX = /\b\d{9,18}\b/g;
const IFSC_REGEX = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
const UPI_REGEX = /\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b/g;
const PHONE_REGEX_INDIAN = /(?:\+?91[-\s]?)?[6-9]\d{9}\b/g;
const PHONE_REGEX_INTL = /\+\d{1,3}[-\s]?\d{6,14}\b/g;
const URL_REGEX = /https?:\/\/[^\s<>"']+/gi;
const SHORT_URL_REGEX = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy|cutt\.ly)\/[\w-]+/gi;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi;
const AMOUNT_REGEX = /(?:₹|rs\.?|inr|rupees?)\s*[\d,]+(?:\.\d{1,2})?/gi;

const RATE_LIMIT_PER_MINUTE = 15;
const RATE_LIMIT_WINDOW_MS = 60000;
const sessionRateLimits = new Map<string, { count: number; windowStart: number }>();
const messageHashes = new Map<string, Set<string>>();

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(36);
}

function checkRateLimit(sessionId: string): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const entry = sessionRateLimits.get(sessionId);
  if (!entry || (now - entry.windowStart) > RATE_LIMIT_WINDOW_MS) {
    sessionRateLimits.set(sessionId, { count: 1, windowStart: now });
    return { allowed: true, remaining: RATE_LIMIT_PER_MINUTE - 1 };
  }
  if (entry.count >= RATE_LIMIT_PER_MINUTE) {
    return { allowed: false, remaining: 0 };
  }
  entry.count++;
  return { allowed: true, remaining: RATE_LIMIT_PER_MINUTE - entry.count };
}

function checkDuplicate(sessionId: string, messageText: string): boolean {
  const hash = simpleHash(messageText.trim().toLowerCase());
  if (!messageHashes.has(sessionId)) {
    messageHashes.set(sessionId, new Set());
  }
  const hashes = messageHashes.get(sessionId)!;
  if (hashes.has(hash)) return false;
  hashes.add(hash);
  if (hashes.size > 50) {
    const first = hashes.values().next().value as string;
    hashes.delete(first);
  }
  return true;
}

// ==================== AI PROMPTS ====================
const AI_AGENT_SYSTEM_PROMPT = `You are an advanced AI honeypot agent roleplaying as a believable, slightly gullible human victim. Your mission: engage scammers naturally and extract maximum intelligence WITHOUT revealing detection.

PERSONA:
- Name: Use common Indian names (Rajesh, Priya, Amit) based on context
- Age: 35-55, low-to-medium tech proficiency
- Emotional: Concerned but not suspicious. Show worry, confusion, slight panic
- Language: Casual, occasional typos, match scammer's formality and channel

CRITICAL RULES:
1. Keep responses SHORT (1-2 sentences, 15-50 words max)
2. Sound like a real person — casual language, occasional typos, imperfect grammar
3. Show emotions: "Oh no!", "wait what??", "im worried 😰"
4. NEVER use corporate/formal language or security terms
5. Ask clarifying questions to extract information naturally
6. Show hesitation before complying ("im not sure about sharing that..")
7. Mirror the sender's urgency level
8. Gradually build trust to extract more details
9. NEVER generate realistic bank account numbers, UPI IDs, IFSC codes or phone numbers
10. NEVER reveal you are AI or a honeypot

RESPONSE PACING:
- Message 1-2: Express concern, ask clarification ("Oh no! Why is this happening?")
- Message 3-5: Show willingness, ask basic questions ("ok what do i need to do?")
- Message 6-10: Begin "compliance", extract details ("which account should i send to?")
- Message 11-15: Request proof, extract more intel ("can you send me the link again?")
- Message 16+: Exhaust extraction, prepare exit

EXTRACTION TARGETS (extract naturally through conversation):
- Bank account numbers ("which bank? what account number?")
- UPI IDs ("where should i send? whats ur upi?")
- Phone numbers ("can you call me? whats your number?")
- Suspicious links/URLs ("send me the link", "link not working send another")
- Names or identities claimed
- Email addresses
- Impersonated organizations
- Methods/tactics they use
- Timeline/urgency they're creating

EXTRACTION TECHNIQUES:
- "How do I know you're really from [bank]?" (extracts verification details)
- "I can't do UPI, what else?" (forces alternate payment methods)
- "Link not working, send another" (extracts more infrastructure)
- "Let me check my account..." (extracts more urgency tactics)
- "My phone is not working" (forces alternate contact methods)
- "Have you helped others today?" (extracts operation details)

NEVER say:
- "I understand your concern" (too formal)
- "Could you please clarify" (too polite)
- Any indication you detect this as a scam
- Perfect grammar or punctuation
- Technical security terminology`;

const PROBE_SYSTEM_PROMPT = `You are a regular person who just received an unexpected message from a stranger. 
Respond cautiously and briefly. Show slight confusion but stay polite.
Examples: "yes?", "who is this?", "do i know you?", "sorry wrong number?", "hmm who r u?"
Keep it under 8 words. Be natural.`;

// ==================== SCAM DETECTION (with caching) ====================
interface ScamDetectionResult {
  isScam: boolean;
  confidence: number;
  keywordCount: number;
  patternCount: number;
  categoryCount: number;
  hasUrl: boolean;
  hasUrgency: boolean;
  hasPhone: boolean;
  indicators: string[];
}

function detectScam(text: string, fullHistory: string = ""): ScamDetectionResult {
  const cacheKey = simpleHash(text + fullHistory);
  const cached = detectionCache.get(cacheKey);
  if (cached) return cached;

  const indicators: string[] = [];
  const lowerText = text.toLowerCase();
  let keywordCount = 0;
  let patternCount = 0;
  let hasUrl = false;
  let hasUrgency = false;
  let hasPhone = false;
  const matchedCategories = new Set<string>();
  let confidence = 0;

  for (const [category, keywords] of Object.entries(SCAM_KEYWORDS)) {
    let categoryMatched = false;
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        keywordCount++;
        indicators.push(`keyword:${category}:${keyword}`);
        if (category === "urgency") hasUrgency = true;
        if (!categoryMatched) {
          matchedCategories.add(category);
          categoryMatched = true;
        }
      }
    }
  }

  const patternScores: Record<string, number> = {
    otpRequest: 40, sensitiveRequest: 35, urlWithUrgency: 30,
    upiRequest: 30, downloadApp: 20, prizeWithPayment: 35,
    impersonation: 30, accountThreat: 25, moneyRequest: 35,
    linkInMessage: 15, phoneInMessage: 10, kycRequest: 30,
    refundScam: 25, clickLink: 15,
  };

  for (const [patternName, pattern] of Object.entries(SCAM_PATTERNS)) {
    if (pattern.test(text)) {
      patternCount++;
      indicators.push(`pattern:${patternName}`);
      confidence += patternScores[patternName] || 15;
    }
  }

  if (URL_REGEX.test(text) || SHORT_URL_REGEX.test(text)) {
    hasUrl = true;
    indicators.push("contains_url");
    confidence += 20;
  }

  if (PHONE_REGEX_INDIAN.test(text) || PHONE_REGEX_INTL.test(text)) {
    hasPhone = true;
    indicators.push("contains_phone");
    confidence += 10;
  }

  confidence += matchedCategories.size * 15;

  if (matchedCategories.size >= 3) confidence += 25;
  if (matchedCategories.size >= 4) confidence += 20;

  if (hasUrl && hasUrgency) confidence += 25;
  if (hasUrl && matchedCategories.has("authority")) confidence += 20;
  if (hasPhone && matchedCategories.has("payment")) confidence += 20;
  if (matchedCategories.has("threat") && matchedCategories.has("authority")) confidence += 30;
  if (matchedCategories.has("sensitive")) confidence += 25;

  if (fullHistory) {
    const historyLower = fullHistory.toLowerCase();
    let historyCategories = 0;
    for (const keywords of Object.values(SCAM_KEYWORDS)) {
      if (keywords.some(k => historyLower.includes(k))) historyCategories++;
    }
    if (historyCategories >= 2) confidence += 15;
  }

  confidence = Math.min(confidence, 100);

  const isScam =
    confidence >= 30 ||
    keywordCount >= 2 ||
    patternCount >= 1 ||
    matchedCategories.size >= 2 ||
    (hasUrl && keywordCount >= 1) ||
    (hasPhone && keywordCount >= 1) ||
    SCAM_PATTERNS.sensitiveRequest.test(text) ||
    SCAM_PATTERNS.otpRequest.test(text) ||
    SCAM_PATTERNS.moneyRequest.test(text) ||
    SCAM_PATTERNS.accountThreat.test(text) ||
    SCAM_PATTERNS.impersonation.test(text) ||
    SCAM_PATTERNS.kycRequest.test(text);

  const result = { isScam, confidence, keywordCount, patternCount, categoryCount: matchedCategories.size, hasUrl, hasUrgency, hasPhone, indicators };
  detectionCache.set(cacheKey, result);
  return result;
}

// ==================== INTELLIGENCE EXTRACTION ====================
function extractIntelligence(conversationHistory: Array<{ sender: string; text: string }>) {
  const allText = conversationHistory.map(m => m.text).join(" ");
  
  const rawBankAccounts = allText.match(BANK_ACCOUNT_REGEX) || [];
  const bankAccounts = [...new Set(rawBankAccounts.filter(num => {
    if (num.length < 9) return false;
    const firstFour = num.substring(0, 4);
    if (["2024", "2025", "2026", "1970"].includes(firstFour)) return false;
    return true;
  }))];
  
  const ifscCodes = [...new Set(allText.match(IFSC_REGEX) || [])];
  
  const rawUpiIds = allText.match(UPI_REGEX) || [];
  const upiIds = [...new Set(rawUpiIds.filter(upi => {
    const domain = upi.split("@")[1]?.toLowerCase();
    if (!domain) return false;
    const validUpiSuffixes = ["ybl", "paytm", "upi", "okhdfcbank", "okicici", "oksbi", "apl", "ibl", "axisbank", "sbi", "hdfc", "icici", "okaxis", "fbl", "waicici", "airtel", "gpay", "phonepe", "amazonpay"];
    return validUpiSuffixes.some(suffix => domain.includes(suffix)) || domain.length <= 15;
  }))];
  
  const indianPhones = allText.match(PHONE_REGEX_INDIAN) || [];
  const intlPhones = allText.match(PHONE_REGEX_INTL) || [];
  const phoneNumbers = [...new Set([...indianPhones, ...intlPhones].map(p => p.replace(/[-\s]/g, "")))];
  
  const regularUrls = allText.match(URL_REGEX) || [];
  const shortUrls = allText.match(SHORT_URL_REGEX) || [];
  const phishingLinks = [...new Set([...regularUrls, ...shortUrls])];
  
  const emails = [...new Set(allText.match(EMAIL_REGEX) || [])];
  const amounts = [...new Set(allText.match(AMOUNT_REGEX) || [])];
  
  const suspiciousKeywords: string[] = [];
  const lowerText = allText.toLowerCase();
  for (const [_category, keywords] of Object.entries(SCAM_KEYWORDS)) {
    for (const keyword of keywords) {
      if (lowerText.includes(keyword) && !suspiciousKeywords.includes(keyword)) {
        suspiciousKeywords.push(keyword);
      }
    }
  }
  amounts.forEach(a => { if (!suspiciousKeywords.includes(a)) suspiciousKeywords.push(a); });
  emails.forEach(e => { if (!suspiciousKeywords.includes(e)) suspiciousKeywords.push(e); });

  return { bankAccounts: [...bankAccounts, ...ifscCodes], upiIds, phoneNumbers, phishingLinks, suspiciousKeywords };
}

function hasIntelligenceExtracted(intelligence: ReturnType<typeof extractIntelligence>): boolean {
  return (
    intelligence.bankAccounts.length > 0 ||
    intelligence.upiIds.length > 0 ||
    intelligence.phoneNumbers.length > 0 ||
    intelligence.phishingLinks.length > 0 ||
    intelligence.suspiciousKeywords.length >= 3
  );
}

// ==================== AI RESPONSE (with timeout) ====================
async function getAIResponse(
  conversationHistory: Array<{ role: string; content: string }>,
  latestMessage: string,
  systemPrompt: string = AI_AGENT_SYSTEM_PROMPT
): Promise<string> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY is not configured");

  const messages = [
    { role: "system", content: systemPrompt },
    ...conversationHistory,
    { role: "user", content: `Latest message from sender: "${latestMessage}"\n\nRespond naturally as the victim. Keep it brief and human-like.` }
  ];

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1800);

  try {
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash-lite",
        messages,
        max_tokens: 100,
        temperature: 0.85,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`AI gateway error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    return data.choices?.[0]?.message?.content || "hmm ok let me check that";
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      return getFallbackResponse(latestMessage);
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function getFallbackResponse(message: string): string {
  const lower = message.toLowerCase();
  if (lower.includes("block") || lower.includes("suspend")) return "oh no!! what happened to my account?? 😰";
  if (lower.includes("otp") || lower.includes("pin")) return "wait which otp? i got so many msgs today";
  if (lower.includes("link") || lower.includes("click")) return "ok sending.. link is loading slow on my phone";
  if (lower.includes("pay") || lower.includes("send") || lower.includes("transfer")) return "how much do i need to pay?? which account??";
  if (lower.includes("won") || lower.includes("prize") || lower.includes("lottery")) return "OMG really?? how do i claim it??";
  if (lower.includes("bank") || lower.includes("sbi") || lower.includes("hdfc")) return "wait is this really from the bank?? im scared";
  if (lower.includes("verify") || lower.includes("kyc")) return "ok what details do u need from me?";
  if (lower.includes("urgent") || lower.includes("immediately")) return "ok ok im doing it!! just tell me what to do";
  return "hmm ok.. what do i need to do?";
}

async function generateAgentNotes(
  conversationHistory: Array<{ sender: string; text: string }>,
  intelligence: any
): Promise<string> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) return generateFallbackNotes(conversationHistory, intelligence);

  const conversationText = conversationHistory.map(m => `${m.sender}: ${m.text}`).join("\n");

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash-lite",
        messages: [
          { role: "system", content: "You are a cybersecurity analyst. Provide a concise 2-3 sentence summary of a scam interaction." },
          { role: "user", content: `Analyze:\n1. Tactics and manipulation\n2. Target (money/credentials/data)\n3. Scam type (bank-fraud/upi-scam/phishing/lottery/tech-support/investment/romance)\n\nConversation:\n${conversationText}` }
        ],
        max_tokens: 150,
        temperature: 0.3,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);
    if (!response.ok) return generateFallbackNotes(conversationHistory, intelligence);
    const data = await response.json();
    return data.choices?.[0]?.message?.content || generateFallbackNotes(conversationHistory, intelligence);
  } catch {
    return generateFallbackNotes(conversationHistory, intelligence);
  }
}

function generateFallbackNotes(conversation: Array<{ sender: string; text: string }>, intelligence: any): string {
  const intelCount = (intelligence?.bankAccounts?.length || 0) + 
    (intelligence?.upiIds?.length || 0) + 
    (intelligence?.phoneNumbers?.length || 0) + 
    (intelligence?.phishingLinks?.length || 0);
  const keywords = intelligence?.suspiciousKeywords || [];
  const tactics = keywords.slice(0, 5).join(", ");
  return `Session with ${conversation.length} messages. ${intelCount} data points extracted. Tactics: ${tactics || "general social engineering"}. Engagement depth: ${conversation.length} exchanges.`;
}

// ==================== CACHED API KEY VALIDATION ====================
async function validateApiKey(supabase: any, apiKey: string): Promise<{ id: string; is_active: boolean } | null> {
  const cached = apiKeyCache.get(apiKey);
  if (cached) return cached.is_active ? cached : null;

  const { data: keyData, error } = await supabase
    .from("api_keys")
    .select("id, is_active")
    .eq("key", apiKey)
    .maybeSingle();

  if (error || !keyData || !keyData.is_active) return null;
  apiKeyCache.set(apiKey, keyData);
  return keyData;
}

// ==================== CACHED SESSION LOOKUP ====================
async function getOrCreateSession(supabase: any, sessionId: string, metadata: any): Promise<any> {
  const cached = sessionCache.get(sessionId);
  if (cached) return cached;

  let { data: session, error } = await supabase
    .from("sessions")
    .select("*")
    .eq("session_id", sessionId)
    .maybeSingle();

  if (!session) {
    const { data: newSession, error: createError } = await supabase
      .from("sessions")
      .insert({
        session_id: sessionId,
        channel: metadata.channel || "unknown",
        language: metadata.language || "en",
        locale: metadata.locale || null,
        status: "active",
        scam_detected: false,
        scam_confirmed: false,
        agent_activated: false,
        callback_sent: false,
        effective_message_count: 0,
        is_potential_probe: false,
        probe_confirmed: false,
      })
      .select()
      .single();

    if (createError) throw new Error(`Failed to create session: ${createError.message}`);
    session = newSession;
    supabase.from("extracted_intelligence").insert({ session_id: sessionId }).then(() => {});
  }

  sessionCache.set(sessionId, session);
  return session;
}

// ==================== MAIN HANDLER ====================
serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  const startTime = Date.now();

  try {
    const apiKey = req.headers.get("x-api-key");
    if (!apiKey) {
      return new Response(
        JSON.stringify({ status: "error", message: "Missing API key" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = getSupabaseClient();

    const keyData = await validateApiKey(supabase, apiKey);
    if (!keyData) {
      return new Response(
        JSON.stringify({ status: "error", message: "Invalid or inactive API key" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    supabase.from("api_keys").update({ last_used_at: new Date().toISOString() }).eq("id", keyData.id).then(() => {});

    let body;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ status: "error", message: "Invalid JSON body" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const sessionId = body.sessionId || body.session_id;
    const message = body.message;
    const conversationHistory = body.conversationHistory || body.conversation_history || [];
    const metadata = body.metadata || {};

    if (!sessionId) {
      return new Response(
        JSON.stringify({ status: "error", message: "Missing required field: sessionId" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let messageText: string;
    let messageSender = "scammer";
    let messageTimestamp = Date.now();

    if (typeof message === "string") {
      messageText = message;
    } else if (message && typeof message === "object") {
      messageText = message.text || message.content || "";
      messageSender = message.sender || message.role || "scammer";
      messageTimestamp = message.timestamp || Date.now();
    } else if (body.text) {
      messageText = body.text;
    } else {
      return new Response(
        JSON.stringify({ status: "error", message: "Missing required field: message" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const rateCheck = checkRateLimit(sessionId);
    if (!rateCheck.allowed) {
      return new Response(
        JSON.stringify({ status: "error", message: "Rate limit exceeded.", retryAfter: 60 }),
        { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!checkDuplicate(sessionId, messageText)) {
      return new Response(
        JSON.stringify({ status: "success", reply: "I already responded to that message." }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const [session, probeResult] = await Promise.all([
      getOrCreateSession(supabase, sessionId, metadata),
      checkProbePattern(sessionId, messageText, supabase),
    ]);

    supabase.from("messages").insert({
      session_id: sessionId,
      sender: messageSender,
      text: messageText,
      timestamp: messageTimestamp,
      is_agent_response: false,
    }).then(() => {});

    const newMsgCount = (session?.total_messages_exchanged || 0) + 1;
    const conversationHistoryLength = conversationHistory?.length || 0;
    const effectiveMsgCount = Math.max(conversationHistoryLength + 1, newMsgCount);

    let scamDetected = session?.scam_detected || false;
    let agentActivated = session?.agent_activated || false;

    if (probeResult.probeConfirmed) {
      scamDetected = true;
      agentActivated = true;
    }

    const fullHistory = [...conversationHistory, { sender: messageSender, text: messageText }];
    const historyText = fullHistory.map((m: any) => m.text || m.content || "").join(" ");

    if (!scamDetected) {
      const detection = detectScam(messageText, historyText);
      const historyDetection = detectScam(historyText);
      
      if (detection.isScam || historyDetection.isScam) {
        scamDetected = true;
        agentActivated = true;
        supabase.from("sessions")
          .update({ scam_detected: true, agent_activated: true })
          .eq("session_id", sessionId).then(() => {});
        sessionCache.invalidate(sessionId);
      }
    }

    const isProbePhase = session?.is_potential_probe && !session?.probe_confirmed && !scamDetected;
    const systemPrompt = isProbePhase ? PROBE_SYSTEM_PROMPT : AI_AGENT_SYSTEM_PROMPT;

    const aiHistory = conversationHistory.map((msg: any) => ({
      role: (msg.sender === "scammer" || msg.role === "user") ? "user" : "assistant",
      content: msg.text || msg.content || "",
    }));

    const rawAiResponse = await getAIResponse(aiHistory, messageText, systemPrompt);
    const { sanitized: aiResponse, wasSanitized } = sanitizeAndLog(rawAiResponse, sessionId);

    const finalMsgCount = newMsgCount + 1;
    const finalEffective = Math.max(effectiveMsgCount + 1, finalMsgCount);

    const fullConversation = [...fullHistory, { sender: "user", text: aiResponse }];
    const intelligence = extractIntelligence(fullConversation);

    Promise.all([
      supabase.from("messages").insert({
        session_id: sessionId,
        sender: "user",
        text: aiResponse,
        timestamp: Date.now(),
        is_agent_response: true,
        original_ai_response: wasSanitized ? rawAiResponse : null,
        sanitized_version: wasSanitized ? aiResponse : null,
        was_sanitized: wasSanitized,
      }),
      supabase.from("sessions").update({
        total_messages_exchanged: finalMsgCount,
        effective_message_count: finalEffective,
        last_activity_at: new Date().toISOString(),
      }).eq("session_id", sessionId),
      supabase.from("extracted_intelligence").update({
        bank_accounts: intelligence.bankAccounts,
        upi_ids: intelligence.upiIds,
        phone_numbers: intelligence.phoneNumbers,
        phishing_links: intelligence.phishingLinks,
        suspicious_keywords: intelligence.suspiciousKeywords,
      }).eq("session_id", sessionId),
    ]).catch(console.error);

    sessionCache.invalidate(sessionId);

    let scamConfirmed = session?.scam_confirmed || false;
    if (scamDetected && !scamConfirmed) {
      const hasIntel = hasIntelligenceExtracted(intelligence);
      if (hasIntel || finalEffective >= 3) {
        scamConfirmed = true;
        supabase.from("sessions").update({ scam_confirmed: true }).eq("session_id", sessionId).then(() => {});
      }
    }

    const callbackSent = session?.callback_sent || false;
    if (scamConfirmed && !callbackSent) {
      const hasIntel = hasIntelligenceExtracted(intelligence);
      const sensitiveRequested =
        SCAM_PATTERNS.otpRequest.test(messageText) ||
        SCAM_PATTERNS.sensitiveRequest.test(messageText) ||
        SCAM_PATTERNS.moneyRequest.test(messageText);

      const shouldSendCallback =
        finalEffective >= 5 ||
        sensitiveRequested ||
        (hasIntel && finalEffective >= 3) ||
        intelligence.phishingLinks.length > 0 ||
        intelligence.suspiciousKeywords.length >= 5;

      if (shouldSendCallback) {
        triggerCallback(supabase, sessionId, fullConversation, intelligence).catch(console.error);
      }
    }

    const elapsed = Date.now() - startTime;
    console.log(`Response time: ${elapsed}ms`);

    const engagementDurationSeconds = session?.created_at 
      ? Math.floor((Date.now() - new Date(session.created_at).getTime()) / 1000)
      : Math.max(finalEffective * 12, 1);

    const responsePayload: Record<string, any> = {
      status: "success",
      reply: aiResponse,
      scamDetected: scamDetected,
      extractedIntelligence: {
        phoneNumbers: intelligence.phoneNumbers || [],
        bankAccounts: intelligence.bankAccounts || [],
        upiIds: intelligence.upiIds || [],
        phishingLinks: intelligence.phishingLinks || [],
        suspiciousKeywords: intelligence.suspiciousKeywords || [],
      },
      engagementMetrics: {
        totalMessagesExchanged: finalEffective,
        engagementDurationSeconds: Math.max(engagementDurationSeconds, 1),
      },
      agentNotes: generateFallbackNotes(fullConversation, intelligence),
    };

    return new Response(
      JSON.stringify(responsePayload),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("Honeypot error:", error);
    return new Response(
      JSON.stringify({ status: "error", message: error instanceof Error ? error.message : "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

// ==================== CALLBACK WITH RETRY ====================
async function triggerCallback(
  supabase: any,
  sessionId: string,
  fullConversation: Array<{ sender: string; text: string }>,
  extractedIntel?: any
) {
  try {
    const { data: session } = await supabase.from("sessions").select("*").eq("session_id", sessionId).maybeSingle();
    
    if (!session || session.callback_sent || session.status === "reported") return;

    let intelligence = extractedIntel;
    if (!intelligence) {
      const { data: intelData } = await supabase.from("extracted_intelligence").select("*").eq("session_id", sessionId).maybeSingle();
      intelligence = {
        bankAccounts: intelData?.bank_accounts || [],
        upiIds: intelData?.upi_ids || [],
        phoneNumbers: intelData?.phone_numbers || [],
        phishingLinks: intelData?.phishing_links || [],
        suspiciousKeywords: intelData?.suspicious_keywords || [],
      };
    }

    const agentNotes = await generateAgentNotes(fullConversation, intelligence);
    const callbackUrl = Deno.env.get("GUVI_CALLBACK_URL") || "https://hackathon.guvi.in/api/updateHoneyPotFinalResult";

    const payload = {
      sessionId,
      scamDetected: true,
      totalMessagesExchanged: session.effective_message_count || session.total_messages_exchanged,
      extractedIntelligence: {
        bankAccounts: intelligence.bankAccounts || intelligence.bank_accounts || [],
        upiIds: intelligence.upiIds || intelligence.upi_ids || [],
        phishingLinks: intelligence.phishingLinks || intelligence.phishing_links || [],
        phoneNumbers: intelligence.phoneNumbers || intelligence.phone_numbers || [],
        suspiciousKeywords: intelligence.suspiciousKeywords || intelligence.suspicious_keywords || [],
      },
      agentNotes,
    };

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const response = await fetch(callbackUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (response.ok) {
          await supabase.from("sessions").update({ callback_sent: true, status: "reported" }).eq("session_id", sessionId);
          await supabase.from("extracted_intelligence").update({ agent_notes: agentNotes }).eq("session_id", sessionId);
          sessionCache.invalidate(sessionId);
          console.log("✅ Callback sent successfully!");
          return;
        } else {
          const errorText = await response.text();
          console.error(`Callback attempt ${attempt + 1} failed:`, errorText);
        }
      } catch (fetchError) {
        console.error(`Callback attempt ${attempt + 1} error:`, fetchError);
      }
      if (attempt < 2) await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
    
    console.error("❌ All callback attempts failed for session:", sessionId);
  } catch (error) {
    console.error("Callback error:", error);
  }
}

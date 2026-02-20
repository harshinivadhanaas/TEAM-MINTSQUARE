-- API Keys Table
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key TEXT UNIQUE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used_at TIMESTAMP
);

-- Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT UNIQUE NOT NULL,
  channel TEXT,
  language TEXT,
  locale TEXT,
  status TEXT DEFAULT 'active',
  scam_detected BOOLEAN DEFAULT false,
  scam_confirmed BOOLEAN DEFAULT false,
  agent_activated BOOLEAN DEFAULT false,
  callback_sent BOOLEAN DEFAULT false,
  total_messages_exchanged INTEGER DEFAULT 0,
  effective_message_count INTEGER DEFAULT 0,
  is_potential_probe BOOLEAN DEFAULT false,
  probe_confirmed BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW(),
  last_activity_at TIMESTAMP DEFAULT NOW()
);

-- Messages Table
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT REFERENCES sessions(session_id),
  sender TEXT NOT NULL,
  text TEXT NOT NULL,
  timestamp BIGINT,
  is_agent_response BOOLEAN DEFAULT false,
  original_ai_response TEXT,
  sanitized_version TEXT,
  was_sanitized BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Extracted Intelligence Table
CREATE TABLE IF NOT EXISTS extracted_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id TEXT UNIQUE REFERENCES sessions(session_id),
  bank_accounts TEXT[] DEFAULT '{}',
  upi_ids TEXT[] DEFAULT '{}',
  phone_numbers TEXT[] DEFAULT '{}',
  phishing_links TEXT[] DEFAULT '{}',
  suspicious_keywords TEXT[] DEFAULT '{}',
  agent_notes TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_sessions_session_id ON sessions(session_id);
CREATE INDEX idx_messages_session_id ON messages(session_id);
CREATE INDEX idx_intelligence_session_id ON extracted_intelligence(session_id);

-- Seed test API key
INSERT INTO api_keys (key, is_active) 
VALUES ('hp_test_key_12345abcdef67890xyz', true)
ON CONFLICT (key) DO NOTHING;
```

**Commit message:** `feat: Add database schema with test API key`

---

## 📋 PRIORITY UPLOAD ORDER

1. ✅ `supabase/functions/honeypot-detect/index.ts` (CRITICAL - your main implementation)
2. ✅ `supabase/functions/_shared/sanitizeAIResponse.ts`
3. ✅ `supabase/functions/_shared/detectProbe.ts`
4. ✅ `supabase/migrations/001_initial_schema.sql`
5. ✅ `package.json`
6. ✅ `tsconfig.json`
7. ✅ `.gitignore` (update existing)
8. ⭐ Frontend files (optional - shows complete system)

---

## 🎯 EXPECTED FINAL STRUCTURE
```
TEAM-MINTSQUARE/
├── README.md                    ✅ Done
├── LICENSE                      ✅ Done
├── .gitignore                   🔄 Update
├── package.json                 ⬆️ Add
├── tsconfig.json                ⬆️ Add
├── vite.config.ts               ⬆️ Add (optional)
├── tailwind.config.ts           ⬆️ Add (optional)
│
├── supabase/
│   ├── functions/
│   │   ├── honeypot-detect/
│   │   │   └── index.ts         🔥 CRITICAL
│   │   └── _shared/
│   │       ├── sanitizeAIResponse.ts  ✅ Important
│   │       └── detectProbe.ts         ✅ Important
│   └── migrations/
│       └── 001_initial_schema.sql     ✅ Important
│
├── src/                         ⭐ Optional but good
│   ├── main.tsx
│   ├── App.tsx
│   └── ...
│
└── docs/                        📚 Documentation
    ├── API.md
    └── ARCHITECTURE.md

-- ConsumeRefreshToken 用 Lua script。
-- KEYS[1]: refresh token のキー
-- ARGV[1]: Used=true に更新した新しい JSON シリアライズ
-- ARGV[2]: PEXPIRE 用の残り TTL (ms)
--
-- 戻り値:
--   {"notfound"}                 — キーが存在しない（or 期限切れ）
--   {"replay", original_json}    — 既に Used=true（replay 検知用に元値を返す）
--   {"ok", original_json}        — 初回消費成功（Used=true に更新済み）
local raw = redis.call("GET", KEYS[1])
if not raw then
    return {"notfound"}
end

-- 内容に "\"Used\":true" を含むかで簡易判定。go-redis 側で json.RawMessage を使っても
-- Lua 内では文字列として扱う。`Used` フィールドは json.Marshal で必ず生成されるため、
-- "\"Used\":true" / "\"Used\":false" の二択で判定できる。
if string.find(raw, '"Used":true', 1, true) then
    return {"replay", raw}
end

-- CAS: 値を Used=true 版に置換し、TTL を維持
redis.call("SET", KEYS[1], ARGV[1])
local ttl = tonumber(ARGV[2])
if ttl and ttl > 0 then
    redis.call("PEXPIRE", KEYS[1], ttl)
end
return {"ok", raw}

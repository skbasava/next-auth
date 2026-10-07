-- Additive tenant-local profile storage; existing identities use legacy fallback.
ALTER TABLE "ScimIdentity" ADD COLUMN "profile" JSONB;

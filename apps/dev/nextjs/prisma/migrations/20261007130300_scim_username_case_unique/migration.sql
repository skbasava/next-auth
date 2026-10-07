-- SCIM userName is caseExact=false. Preserve display spelling while preventing
-- case variants within a tenant, including concurrent/direct database writes.
CREATE UNIQUE INDEX "ScimIdentity_orgId_userName_case_unique"
ON "ScimIdentity" ("orgId", lower("userName"));

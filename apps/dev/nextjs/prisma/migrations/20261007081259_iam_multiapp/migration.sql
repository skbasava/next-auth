-- CreateEnum
CREATE TYPE "ApiKeyPurpose" AS ENUM ('IAM', 'SCIM');

-- CreateTable
CREATE TABLE "Account" (
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("provider","providerAccountId")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "sessionToken" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT,
    "email" TEXT,
    "emailVerified" TIMESTAMP(3),
    "image" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "passwordHash" TEXT,
    "sessionVersion" INTEGER NOT NULL DEFAULT 0,
    "systemAdmin" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationToken" (
    "identifier" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL
);

-- CreateTable
CREATE TABLE "Authenticator" (
    "id" TEXT NOT NULL,
    "credentialID" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "credentialPublicKey" TEXT NOT NULL,
    "counter" INTEGER NOT NULL,
    "credentialDeviceType" TEXT NOT NULL,
    "credentialBackedUp" BOOLEAN NOT NULL,
    "transports" TEXT,

    CONSTRAINT "Authenticator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "authorizationRevision" INTEGER NOT NULL DEFAULT 0,
    "requireMfa" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Membership" (
    "orgId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Membership_pkey" PRIMARY KEY ("orgId","userId")
);

-- CreateTable
CREATE TABLE "Role" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "Role_pkey" PRIMARY KEY ("orgId","id")
);

-- CreateTable
CREATE TABLE "Permission" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "appId" TEXT,

    CONSTRAINT "Permission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RolePermission" (
    "orgId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,

    CONSTRAINT "RolePermission_pkey" PRIMARY KEY ("orgId","roleId","permissionId")
);

-- CreateTable
CREATE TABLE "UserRole" (
    "orgId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,

    CONSTRAINT "UserRole_pkey" PRIMARY KEY ("orgId","userId","roleId")
);

-- CreateTable
CREATE TABLE "Application" (
    "webhookUrl" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "integrationSecretHash" TEXT NOT NULL,
    "credentialExpiresAt" TIMESTAMP(3),
    "credentialRevokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Application_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AppResource" (
    "actions" TEXT[],
    "appId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "AppResource_pkey" PRIMARY KEY ("appId","name")
);

-- CreateTable
CREATE TABLE "AppRole" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "AppRole_pkey" PRIMARY KEY ("appId","id")
);

-- CreateTable
CREATE TABLE "AppRolePermission" (
    "appId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,

    CONSTRAINT "AppRolePermission_pkey" PRIMARY KEY ("appId","roleId","permissionId")
);

-- CreateTable
CREATE TABLE "OrgAppAccess" (
    "orgId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "requireMfa" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "OrgAppAccess_pkey" PRIMARY KEY ("orgId","appId")
);

-- CreateTable
CREATE TABLE "UserAppRole" (
    "orgId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,

    CONSTRAINT "UserAppRole_pkey" PRIMARY KEY ("orgId","userId","appId","roleId")
);

-- CreateTable
CREATE TABLE "Invitation" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "acceptedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Invitation_pkey" PRIMARY KEY ("orgId","id")
);

-- CreateTable
CREATE TABLE "InvitationRole" (
    "orgId" TEXT NOT NULL,
    "invitationId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,

    CONSTRAINT "InvitationRole_pkey" PRIMARY KEY ("orgId","invitationId","roleId")
);

-- CreateTable
CREATE TABLE "ApiKey" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "purpose" "ApiKeyPurpose" NOT NULL,
    "permissionKeys" TEXT[],
    "createdByUserId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "ApiKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IamSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "sessionVersion" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "mfaVerifiedAt" TIMESTAMP(3),

    CONSTRAINT "IamSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MfaCredential" (
    "userId" TEXT NOT NULL,
    "encryptedSecret" TEXT,
    "pendingEncryptedSecret" TEXT,
    "pendingExpiresAt" TIMESTAMP(3),
    "enrolledAt" TIMESTAMP(3),
    "lastAcceptedStep" BIGINT,
    "failedAttempts" INTEGER NOT NULL DEFAULT 0,
    "attemptWindowStartedAt" TIMESTAMP(3),
    "lockedUntil" TIMESTAMP(3),
    "pendingLastAcceptedStep" BIGINT,

    CONSTRAINT "MfaCredential_pkey" PRIMARY KEY ("userId")
);

-- CreateTable
CREATE TABLE "BackupCode" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "BackupCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "orgId" TEXT,
    "actorUserId" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "requestId" TEXT NOT NULL,
    "ip" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScimIdentity" (
    "orgId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "id" TEXT NOT NULL,
    "externalId" TEXT,
    "userName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ScimIdentity_pkey" PRIMARY KEY ("orgId","userId")
);

-- CreateIndex
CREATE UNIQUE INDEX "Session_sessionToken_key" ON "Session"("sessionToken");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_token_key" ON "VerificationToken"("token");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_identifier_token_key" ON "VerificationToken"("identifier", "token");

-- CreateIndex
CREATE UNIQUE INDEX "Authenticator_credentialID_key" ON "Authenticator"("credentialID");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_slug_key" ON "Organization"("slug");

-- CreateIndex
CREATE INDEX "Membership_userId_active_idx" ON "Membership"("userId", "active");

-- CreateIndex
CREATE UNIQUE INDEX "Role_orgId_name_key" ON "Role"("orgId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Permission_key_key" ON "Permission"("key");

-- CreateIndex
CREATE UNIQUE INDEX "Permission_appId_id_key" ON "Permission"("appId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "Permission_appId_resource_action_key" ON "Permission"("appId", "resource", "action");

-- CreateIndex
CREATE UNIQUE INDEX "Application_slug_key" ON "Application"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "AppRole_appId_name_key" ON "AppRole"("appId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Invitation_tokenHash_key" ON "Invitation"("tokenHash");

-- CreateIndex
CREATE INDEX "Invitation_orgId_email_idx" ON "Invitation"("orgId", "email");

-- CreateIndex
CREATE UNIQUE INDEX "ApiKey_prefix_key" ON "ApiKey"("prefix");

-- CreateIndex
CREATE INDEX "ApiKey_orgId_createdAt_id_idx" ON "ApiKey"("orgId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "IamSession_userId_expiresAt_id_idx" ON "IamSession"("userId", "expiresAt", "id");

-- CreateIndex
CREATE INDEX "BackupCode_userId_consumedAt_idx" ON "BackupCode"("userId", "consumedAt");

-- CreateIndex
CREATE INDEX "AuditLog_orgId_createdAt_id_idx" ON "AuditLog"("orgId", "createdAt", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScimIdentity_orgId_id_key" ON "ScimIdentity"("orgId", "id");

-- CreateIndex
CREATE UNIQUE INDEX "ScimIdentity_orgId_externalId_key" ON "ScimIdentity"("orgId", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "ScimIdentity_orgId_userName_key" ON "ScimIdentity"("orgId", "userName");

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Authenticator" ADD CONSTRAINT "Authenticator_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Membership" ADD CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Role" ADD CONSTRAINT "Role_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Permission" ADD CONSTRAINT "Permission_appId_fkey" FOREIGN KEY ("appId") REFERENCES "Application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_orgId_roleId_fkey" FOREIGN KEY ("orgId", "roleId") REFERENCES "Role"("orgId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "Permission"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_orgId_userId_fkey" FOREIGN KEY ("orgId", "userId") REFERENCES "Membership"("orgId", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_orgId_roleId_fkey" FOREIGN KEY ("orgId", "roleId") REFERENCES "Role"("orgId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppResource" ADD CONSTRAINT "AppResource_appId_fkey" FOREIGN KEY ("appId") REFERENCES "Application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppRole" ADD CONSTRAINT "AppRole_appId_fkey" FOREIGN KEY ("appId") REFERENCES "Application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppRolePermission" ADD CONSTRAINT "AppRolePermission_appId_roleId_fkey" FOREIGN KEY ("appId", "roleId") REFERENCES "AppRole"("appId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AppRolePermission" ADD CONSTRAINT "AppRolePermission_appId_permissionId_fkey" FOREIGN KEY ("appId", "permissionId") REFERENCES "Permission"("appId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgAppAccess" ADD CONSTRAINT "OrgAppAccess_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgAppAccess" ADD CONSTRAINT "OrgAppAccess_appId_fkey" FOREIGN KEY ("appId") REFERENCES "Application"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAppRole" ADD CONSTRAINT "UserAppRole_orgId_userId_fkey" FOREIGN KEY ("orgId", "userId") REFERENCES "Membership"("orgId", "userId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAppRole" ADD CONSTRAINT "UserAppRole_orgId_appId_fkey" FOREIGN KEY ("orgId", "appId") REFERENCES "OrgAppAccess"("orgId", "appId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAppRole" ADD CONSTRAINT "UserAppRole_appId_roleId_fkey" FOREIGN KEY ("appId", "roleId") REFERENCES "AppRole"("appId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Invitation" ADD CONSTRAINT "Invitation_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InvitationRole" ADD CONSTRAINT "InvitationRole_orgId_invitationId_fkey" FOREIGN KEY ("orgId", "invitationId") REFERENCES "Invitation"("orgId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InvitationRole" ADD CONSTRAINT "InvitationRole_orgId_roleId_fkey" FOREIGN KEY ("orgId", "roleId") REFERENCES "Role"("orgId", "id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ApiKey" ADD CONSTRAINT "ApiKey_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IamSession" ADD CONSTRAINT "IamSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MfaCredential" ADD CONSTRAINT "MfaCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BackupCode" ADD CONSTRAINT "BackupCode_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScimIdentity" ADD CONSTRAINT "ScimIdentity_orgId_userId_fkey" FOREIGN KEY ("orgId", "userId") REFERENCES "Membership"("orgId", "userId") ON DELETE CASCADE ON UPDATE CASCADE;
-- Nullable application scopes need an explicit PostgreSQL partial index.
CREATE UNIQUE INDEX "Permission_core_resource_action_key"
ON "Permission" ("resource", "action") WHERE "appId" IS NULL;

-- Lock the referenced permission until commit. This conflicts with scope updates,
-- including non-key appId updates which ordinary FK KEY SHARE locks permit.
CREATE FUNCTION iam_core_role_permission_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE permission_app text;
BEGIN
  SELECT "appId" INTO permission_app FROM "Permission"
  WHERE id = NEW."permissionId" FOR UPDATE;
  IF permission_app IS NOT NULL THEN
    RAISE EXCEPTION 'core role requires core permission' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER "RolePermission_core_scope"
AFTER INSERT OR UPDATE ON "RolePermission"
NOT DEFERRABLE FOR EACH ROW EXECUTE FUNCTION iam_core_role_permission_scope();

-- The update already holds the permission row lock; the reciprocal trigger
-- prevents scope changes from leaving existing core assignments invalid.
CREATE FUNCTION iam_permission_core_scope_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW."appId" IS NOT NULL AND EXISTS (
    SELECT 1 FROM "RolePermission" WHERE "permissionId" = NEW.id
  ) THEN
    RAISE EXCEPTION 'assigned core permission cannot become app scoped' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER "Permission_core_scope_update"
AFTER UPDATE ON "Permission"
NOT DEFERRABLE FOR EACH ROW EXECUTE FUNCTION iam_permission_core_scope_update();

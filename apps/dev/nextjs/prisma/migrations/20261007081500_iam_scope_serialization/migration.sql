CREATE OR REPLACE FUNCTION iam_core_role_permission_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE permission_app text;
BEGIN
  SELECT "appId" INTO permission_app FROM "Permission"
  WHERE id = NEW."permissionId" FOR UPDATE;
  IF permission_app IS NOT NULL THEN
    RAISE EXCEPTION 'core role requires core permission' USING ERRCODE = '23514';
  END IF;
  -- Advance the tuple version too: stale REPEATABLE READ / SERIALIZABLE
  -- scope updates must fail serialization rather than miss a newly added link.
  UPDATE "Permission" SET id = id WHERE id = NEW."permissionId";
  RETURN NEW;
END;
$$;

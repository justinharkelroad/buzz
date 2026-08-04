-- Immutable DM participant sets and channel shape.
--
-- DMs are identified by an order-independent participant_hash and must be
-- private. Adding a participant creates a new DM; no in-place membership,
-- type, visibility, or hash mutation is permitted. Deferred participant-set
-- checks allow create_dm() to insert the channel followed by its 2-9 members
-- in one transaction while rejecting mutations by rolling old binaries or
-- direct database callers at commit.

LOCK TABLE channels IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE channel_members IN SHARE ROW EXCLUSIVE MODE;

-- Brownfield preflight: refuse to install guards over an already inconsistent
-- active DM. Operators must repair the row/member set and retry the migration.
DO $$
DECLARE
    bad RECORD;
BEGIN
    SELECT
        c.community_id,
        c.id,
        c.visibility::text AS visibility,
        c.participant_hash,
        members.member_count,
        members.pubkeys_valid,
        members.roles_valid,
        members.active_hash
    INTO bad
    FROM channels c
    CROSS JOIN LATERAL (
        SELECT
            COUNT(*)::integer AS member_count,
            COALESCE(BOOL_AND(octet_length(cm.pubkey) = 32), FALSE) AS pubkeys_valid,
            COALESCE(BOOL_AND(cm.role = 'member'), FALSE) AS roles_valid,
            pg_catalog.sha256(
                COALESCE(string_agg(cm.pubkey, ''::bytea ORDER BY cm.pubkey), ''::bytea)
            ) AS active_hash
        FROM channel_members cm
        WHERE cm.community_id = c.community_id
          AND cm.channel_id = c.id
          AND cm.removed_at IS NULL
    ) members
    WHERE c.channel_type = 'dm'
      AND c.deleted_at IS NULL
      AND (
          c.visibility <> 'private'
          OR c.participant_hash IS NULL
          OR octet_length(c.participant_hash) <> 32
          OR members.member_count NOT BETWEEN 2 AND 9
          OR NOT members.pubkeys_valid
          OR NOT members.roles_valid
          OR members.active_hash IS DISTINCT FROM c.participant_hash
      )
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'immutable DM migration blocked: active DM %.% has visibility %, % members, or participant_hash mismatch',
            bad.community_id,
            bad.id,
            bad.visibility,
            bad.member_count
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$;

ALTER TABLE channels
    ADD CONSTRAINT chk_channels_active_dm_shape CHECK (
        deleted_at IS NOT NULL
        OR (
            channel_type = 'dm'
            AND visibility = 'private'
            AND participant_hash IS NOT NULL
            AND octet_length(participant_hash) = 32
        )
        OR (
            channel_type <> 'dm'
            AND participant_hash IS NULL
        )
    );

CREATE FUNCTION guard_immutable_dm_channel_shape() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.channel_type = 'dm' THEN
        IF NEW.visibility <> 'private' THEN
            RAISE EXCEPTION 'DM channel visibility is immutable and must be private'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.participant_hash IS NULL OR octet_length(NEW.participant_hash) <> 32 THEN
            RAISE EXCEPTION 'DM participant_hash must be exactly 32 bytes'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.participant_hash IS NOT NULL THEN
        RAISE EXCEPTION 'non-DM channels cannot carry participant_hash'
            USING ERRCODE = 'check_violation';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.participant_hash IS DISTINCT FROM NEW.participant_hash THEN
            RAISE EXCEPTION 'channels.participant_hash is immutable after insert'
                USING ERRCODE = 'check_violation';
        END IF;
        IF (OLD.channel_type = 'dm' OR NEW.channel_type = 'dm')
           AND OLD.channel_type IS DISTINCT FROM NEW.channel_type THEN
            RAISE EXCEPTION 'channels cannot transition into or out of DM type'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_channels_immutable_dm_shape
    BEFORE INSERT OR UPDATE ON channels
    FOR EACH ROW EXECUTE FUNCTION guard_immutable_dm_channel_shape();

CREATE FUNCTION assert_immutable_dm_participant_set(
    checked_community_id UUID,
    checked_channel_id UUID
) RETURNS VOID AS $$
DECLARE
    stored_type channel_type;
    stored_hash BYTEA;
    member_count INTEGER;
    pubkeys_valid BOOLEAN;
    roles_valid BOOLEAN;
    active_hash BYTEA;
BEGIN
    SELECT channel_type, participant_hash
    INTO stored_type, stored_hash
    FROM channels
    WHERE community_id = checked_community_id
      AND id = checked_channel_id;

    -- Hard-deleted channels (including ON DELETE CASCADE member cleanup) no
    -- longer have a participant-set invariant to verify.
    IF NOT FOUND OR stored_type <> 'dm' THEN
        RETURN;
    END IF;

    SELECT
        COUNT(*)::integer,
        COALESCE(BOOL_AND(octet_length(pubkey) = 32), FALSE),
        COALESCE(BOOL_AND(role = 'member'), FALSE),
        pg_catalog.sha256(
            COALESCE(string_agg(pubkey, ''::bytea ORDER BY pubkey), ''::bytea)
        )
    INTO member_count, pubkeys_valid, roles_valid, active_hash
    FROM channel_members
    WHERE community_id = checked_community_id
      AND channel_id = checked_channel_id
      AND removed_at IS NULL;

    IF member_count NOT BETWEEN 2 AND 9
       OR NOT pubkeys_valid
       OR NOT roles_valid
       OR active_hash IS DISTINCT FROM stored_hash THEN
        RAISE EXCEPTION
            'immutable DM participant set mismatch for %.% (active members: %)',
            checked_community_id,
            checked_channel_id,
            member_count
            USING ERRCODE = 'check_violation';
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION verify_immutable_dm_channel_trigger() RETURNS TRIGGER AS $$
BEGIN
    PERFORM assert_immutable_dm_participant_set(NEW.community_id, NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER trg_channels_verify_immutable_dm_participants
    AFTER INSERT OR UPDATE ON channels
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION verify_immutable_dm_channel_trigger();

CREATE FUNCTION verify_immutable_dm_member_trigger() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM assert_immutable_dm_participant_set(OLD.community_id, OLD.channel_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND (
           TG_OP <> 'UPDATE'
           OR NEW.community_id IS DISTINCT FROM OLD.community_id
           OR NEW.channel_id IS DISTINCT FROM OLD.channel_id
       ) THEN
        PERFORM assert_immutable_dm_participant_set(NEW.community_id, NEW.channel_id);
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER trg_channel_members_verify_immutable_dm_participants
    AFTER INSERT OR UPDATE OR DELETE ON channel_members
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION verify_immutable_dm_member_trigger();

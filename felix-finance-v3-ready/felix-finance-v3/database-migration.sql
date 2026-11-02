-- FELIX FINANCE V3 migration
-- Run AFTER the initial schema has been created.
-- This migration does not delete existing financial data.

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS last_login_at timestamptz,
  ADD COLUMN IF NOT EXISTS last_password_change_at timestamptz;

-- Profile roles and account status must only be changed by trusted server functions.
REVOKE INSERT, UPDATE, DELETE ON public.profiles FROM anon, authenticated;
GRANT SELECT ON public.profiles TO authenticated;

-- Financial data can be written by an authenticated user only for their own owner_id.
-- Existing RLS policies are retained; these grants do not bypass RLS.
GRANT SELECT, INSERT, DELETE ON public.accounts, public.categories,
  public.transactions, public.budgets, public.savings_goals TO authenticated;

REVOKE INSERT, UPDATE, DELETE ON public.activity_logs FROM anon, authenticated;
GRANT SELECT ON public.activity_logs TO authenticated;

-- Generic audit trigger for owned financial tables other than transactions
-- (transactions already has trg_audit_transactions from the initial schema).
CREATE OR REPLACE FUNCTION public.audit_owned_row()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_old jsonb;
  v_new jsonb;
  v_owner uuid;
  v_record text;
  v_action text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    v_old := to_jsonb(OLD);
    v_new := NULL;
    v_owner := (v_old ->> 'owner_id')::uuid;
    v_record := v_old ->> 'id';
    v_action := 'DELETE';
  ELSIF TG_OP = 'UPDATE' THEN
    v_old := to_jsonb(OLD);
    v_new := to_jsonb(NEW);
    v_owner := (v_new ->> 'owner_id')::uuid;
    v_record := v_new ->> 'id';
    v_action := 'UPDATE';
  ELSE
    v_old := NULL;
    v_new := to_jsonb(NEW);
    v_owner := (v_new ->> 'owner_id')::uuid;
    v_record := v_new ->> 'id';
    v_action := 'INSERT';
  END IF;

  INSERT INTO public.activity_logs
    (actor_id, owner_id, action, table_name, record_id, old_data, new_data)
  VALUES
    (auth.uid(), v_owner, v_action, TG_TABLE_NAME, v_record, v_old, v_new);

  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_accounts ON public.accounts;
CREATE TRIGGER trg_audit_accounts
AFTER INSERT OR UPDATE OR DELETE ON public.accounts
FOR EACH ROW EXECUTE FUNCTION public.audit_owned_row();

DROP TRIGGER IF EXISTS trg_audit_categories ON public.categories;
CREATE TRIGGER trg_audit_categories
AFTER INSERT OR UPDATE OR DELETE ON public.categories
FOR EACH ROW EXECUTE FUNCTION public.audit_owned_row();

DROP TRIGGER IF EXISTS trg_audit_budgets ON public.budgets;
CREATE TRIGGER trg_audit_budgets
AFTER INSERT OR UPDATE OR DELETE ON public.budgets
FOR EACH ROW EXECUTE FUNCTION public.audit_owned_row();

DROP TRIGGER IF EXISTS trg_audit_savings_goals ON public.savings_goals;
CREATE TRIGGER trg_audit_savings_goals
AFTER INSERT OR UPDATE OR DELETE ON public.savings_goals
FOR EACH ROW EXECUTE FUNCTION public.audit_owned_row();

REVOKE ALL ON FUNCTION public.audit_owned_row() FROM PUBLIC, anon, authenticated;

CREATE INDEX IF NOT EXISTS idx_transactions_owner_date
  ON public.transactions(owner_id, transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_activity_logs_owner_created
  ON public.activity_logs(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_username
  ON public.profiles(username);

SELECT 'FELIX FINANCE V3 MIGRATION READY' AS status;

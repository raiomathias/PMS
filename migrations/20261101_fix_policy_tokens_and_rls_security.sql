-- PMS: fix policy-link token constraint and close RLS gaps.
-- Applied to production Supabase project on 2026-11-01.
BEGIN;

-- The public policy page and its RPCs use 128-bit (32 hex chars) tokens.
ALTER TABLE public.politicas_links
  DROP CONSTRAINT IF EXISTS politicas_links_codigo_format;
ALTER TABLE public.politicas_links
  ADD CONSTRAINT politicas_links_codigo_format
  CHECK (codigo ~ '^[0-9A-F]{32}$');

-- Payment reason details are read by the reservation UI, but only for
-- payments belonging to a reservation/building the current staff member can access.
DROP POLICY IF EXISTS pagos_motivos_lectura_autorizada ON public.pagos_motivos;
CREATE POLICY pagos_motivos_lectura_autorizada
  ON public.pagos_motivos
  FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1
      FROM public.pagos p
      JOIN public.reservas r ON r.id = p.reserva_id
      JOIN public.unidades u ON u.id = r.unidad_id
      WHERE p.id = pagos_motivos.pago_id
        AND public.pms_rol() IN ('recepcion','administracion','gerencia','sysadmin')
        AND public.puede_ver_edificio(u.edificio_id)
    )
  );

-- The UI only reads this table directly. Writes remain inside validated RPCs.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON TABLE public.pagos_motivos FROM authenticated;
GRANT SELECT ON TABLE public.pagos_motivos TO authenticated;

-- The historical import staging table is not used by the live frontend.
-- Keep it inaccessible through the Data API to authenticated/anonymous clients.
REVOKE ALL PRIVILEGES ON TABLE public.import_reservas_historicas
  FROM anon, authenticated;

-- Harden application-owned SECURITY DEFINER functions against temporary
-- schema object shadowing. pg_temp is deliberately last in the fixed path.
DO $$
DECLARE
  f record;
BEGIN
  FOR f IN
    SELECT p.oid, n.nspname, p.proname,
           pg_get_function_identity_arguments(p.oid) AS identity_args
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.prokind = 'f'
      AND p.prosecdef
      AND p.proowner = 'postgres'::regrole
      AND p.proname <> 'rls_auto_enable'
  LOOP
    EXECUTE format(
      'ALTER FUNCTION %I.%I(%s) SET search_path TO pg_catalog, public, auth, pg_temp',
      f.nspname, f.proname, f.identity_args
    );
  END LOOP;
END
$$;

COMMIT;

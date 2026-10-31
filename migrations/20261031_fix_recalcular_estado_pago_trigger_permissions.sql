-- Corrige la ejecución de recálculo de pagos desde triggers.
-- Los usuarios autenticados NO reciben EXECUTE sobre recalcular_estado_pago;
-- los triggers se ejecutan con el propietario de la función (postgres).
BEGIN;

ALTER FUNCTION public.trg_recalcular_pago_hijo()
  SECURITY DEFINER;
ALTER FUNCTION public.trg_recalcular_pago_hijo()
  SET search_path = pg_catalog, public, auth, pg_temp;

ALTER FUNCTION public.trg_recalcular_pago_reserva()
  SECURITY DEFINER;
ALTER FUNCTION public.trg_recalcular_pago_reserva()
  SET search_path = pg_catalog, public, auth, pg_temp;

ALTER FUNCTION public.recalcular_estado_pago(uuid)
  SECURITY DEFINER;
ALTER FUNCTION public.recalcular_estado_pago(uuid)
  SET search_path = pg_catalog, public, pg_temp;

REVOKE ALL ON FUNCTION public.trg_recalcular_pago_hijo()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.trg_recalcular_pago_reserva()
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.recalcular_estado_pago(uuid)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.recalcular_estado_pago(uuid)
  TO service_role;

COMMIT;

-- ============================================================
-- PMS · Corrección RLS de reclamos y sugerencias
-- Fecha: 2026-10-13
-- Ejecutar en Supabase SQL Editor sobre el proyecto activo.
-- Idempotente: se puede volver a ejecutar sin duplicar políticas.
-- ============================================================

-- La función centraliza la autorización y aplica el alcance por edificio.
-- Administración, Gerencia y SysAdmin acceden a todos los edificios;
-- Recepción solo accede a reclamos de edificios asignados en perfiles_edificios.
CREATE OR REPLACE FUNCTION public.puede_acceder_reclamo(p_reserva_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, auth
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.perfiles p
    JOIN public.reservas r ON r.id = p_reserva_id
    JOIN public.unidades u ON u.id = r.unidad_id
    WHERE p.id = auth.uid()
      AND p.activo = true
      AND p.rol::text IN ('recepcion', 'administracion', 'gerencia', 'sysadmin')
      AND (
        p.rol::text IN ('administracion', 'gerencia', 'sysadmin')
        OR EXISTS (
          SELECT 1
          FROM public.perfiles_edificios pe
          WHERE pe.perfil_id = p.id
            AND pe.edificio_id = u.edificio_id
        )
      )
  );
$function$;

REVOKE ALL ON FUNCTION public.puede_acceder_reclamo(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.puede_acceder_reclamo(uuid) TO authenticated;

ALTER TABLE public.reclamos_sugerencias ENABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLE public.reclamos_sugerencias TO authenticated;

DROP POLICY IF EXISTS reclamos_sugerencias_select_por_reserva
ON public.reclamos_sugerencias;
CREATE POLICY reclamos_sugerencias_select_por_reserva
ON public.reclamos_sugerencias
FOR SELECT TO authenticated
USING (public.puede_acceder_reclamo(reserva_id));

DROP POLICY IF EXISTS reclamos_sugerencias_insert_por_reserva
ON public.reclamos_sugerencias;
CREATE POLICY reclamos_sugerencias_insert_por_reserva
ON public.reclamos_sugerencias
FOR INSERT TO authenticated
WITH CHECK (
  public.puede_acceder_reclamo(reserva_id)
  AND creado_por = auth.uid()
);

DROP POLICY IF EXISTS reclamos_sugerencias_update_por_reserva
ON public.reclamos_sugerencias;
CREATE POLICY reclamos_sugerencias_update_por_reserva
ON public.reclamos_sugerencias
FOR UPDATE TO authenticated
USING (public.puede_acceder_reclamo(reserva_id))
WITH CHECK (public.puede_acceder_reclamo(reserva_id));

DROP POLICY IF EXISTS reclamos_sugerencias_delete_por_reserva
ON public.reclamos_sugerencias;
CREATE POLICY reclamos_sugerencias_delete_por_reserva
ON public.reclamos_sugerencias
FOR DELETE TO authenticated
USING (public.puede_acceder_reclamo(reserva_id));

-- Comprobación posterior:
-- SELECT policyname, cmd, roles, qual, with_check
-- FROM pg_policies
-- WHERE schemaname = 'public'
--   AND tablename = 'reclamos_sugerencias'
-- ORDER BY policyname;

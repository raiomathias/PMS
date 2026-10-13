-- ============================================================
-- PMS v1.10.8 · 2026-10-13
-- 1) Eliminación lógica global de mensajes del Buzón.
-- 2) Pago anticipado automático para reservas nuevas de Airbnb.
-- Ejecutar este archivo completo en Supabase SQL Editor.
-- ============================================================

BEGIN;

ALTER TABLE public.buzon_mensajes
  ADD COLUMN IF NOT EXISTS eliminado_en timestamptz,
  ADD COLUMN IF NOT EXISTS eliminado_por uuid
    REFERENCES public.perfiles(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS eliminacion_tipo text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'buzon_mensajes_eliminacion_tipo_check'
      AND conrelid = 'public.buzon_mensajes'::regclass
  ) THEN
    ALTER TABLE public.buzon_mensajes
      ADD CONSTRAINT buzon_mensajes_eliminacion_tipo_check
      CHECK (eliminacion_tipo IS NULL OR eliminacion_tipo IN ('autor','administrador'));
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.buzon_eliminar_mensaje(p_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  v_remitente uuid;
  v_eliminado_en timestamptz;
  v_rol text;
  v_tipo text;
  v_mensaje text;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Sesión no válida';
  END IF;

  SELECT b.remitente_id, b.eliminado_en
    INTO v_remitente, v_eliminado_en
  FROM public.buzon_mensajes b
  WHERE b.id = p_id AND b.activo = true
  FOR UPDATE;

  IF NOT FOUND THEN RAISE EXCEPTION 'Mensaje no encontrado o no disponible'; END IF;
  IF v_eliminado_en IS NOT NULL THEN RAISE EXCEPTION 'El mensaje ya fue eliminado'; END IF;

  SELECT lower(p.rol::text)
    INTO v_rol
  FROM public.perfiles p
  WHERE p.id = auth.uid() AND p.activo = true;

  IF v_rol IS NULL THEN RAISE EXCEPTION 'Usuario sin perfil activo'; END IF;

  -- Si Gerencia elimina su propio mensaje, se considera eliminación del autor.
  IF v_remitente = auth.uid() THEN
    v_tipo := 'autor';
    v_mensaje := 'Mensaje eliminado por el autor';
  ELSIF v_rol IN ('gerencia','sysadmin','system_admin','systemadmin') THEN
    v_tipo := 'administrador';
    v_mensaje := 'Mensaje eliminado por un administrador';
  ELSE
    RAISE EXCEPTION 'Solo puedes eliminar tus propios mensajes; Gerencia+ puede eliminar los de otros usuarios';
  END IF;

  UPDATE public.buzon_mensajes
     SET mensaje = v_mensaje,
         eliminado_en = now(),
         eliminado_por = auth.uid(),
         eliminacion_tipo = v_tipo
   WHERE id = p_id AND eliminado_en IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION public.buzon_eliminar_mensaje(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.buzon_eliminar_mensaje(uuid) TO authenticated;

DROP FUNCTION IF EXISTS public.buzon_listar();

CREATE FUNCTION public.buzon_listar()
RETURNS TABLE(
  id uuid,
  audiencia text,
  receptor_id uuid,
  mensaje text,
  creado_en timestamptz,
  leido_en timestamptz,
  remitente_id uuid,
  remitente_nombre text,
  eliminado_en timestamptz,
  eliminacion_tipo text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Sesión no válida'; END IF;

  RETURN QUERY
  SELECT
    b.id, b.audiencia, b.receptor_id, b.mensaje,
    b.creado_en, l.leido_en, b.remitente_id,
    COALESCE(p.nombre_completo,'Usuario')::text,
    b.eliminado_en, b.eliminacion_tipo
  FROM public.buzon_mensajes b
  LEFT JOIN public.perfiles p ON p.id = b.remitente_id
  LEFT JOIN public.buzon_lecturas l
    ON l.mensaje_id = b.id AND l.usuario_id = auth.uid()
  WHERE b.activo = true
    AND NOT EXISTS (
      SELECT 1 FROM public.buzon_limpiezas_globales g WHERE g.mensaje_id = b.id
    )
    AND NOT EXISTS (
      SELECT 1 FROM public.buzon_ocultos o
      WHERE o.usuario_id = auth.uid() AND o.mensaje_id = b.id
    )
    AND public.buzon_puede_ver_audiencia(b.audiencia)
  ORDER BY b.creado_en DESC
  LIMIT 100;
END;
$$;

GRANT EXECUTE ON FUNCTION public.buzon_listar() TO authenticated;

-- Añadir el método contable "airbnb" al enum real de pagos sin
-- asumir su nombre. Se ejecuta antes de crear el RPC y la etiqueta se
-- utiliza únicamente después del COMMIT de esta migración.
DO $
DECLARE
  v_metodo_type regtype;
  v_es_enum boolean;
BEGIN
  SELECT a.atttypid::regtype INTO v_metodo_type
  FROM pg_attribute a
  WHERE a.attrelid = 'public.pagos'::regclass
    AND a.attname = 'metodo'
    AND NOT a.attisdropped;

  SELECT t.typtype = 'e' INTO v_es_enum
  FROM pg_type t
  WHERE t.oid = v_metodo_type::oid;

  IF v_metodo_type IS NULL OR NOT COALESCE(v_es_enum,false) THEN
    RAISE EXCEPTION 'La columna public.pagos.metodo no utiliza un tipo enum; revisar el esquema antes de migrar';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_enum
    WHERE enumtypid = v_metodo_type::oid AND enumlabel = 'airbnb'
  ) THEN
    EXECUTE format('ALTER TYPE %s ADD VALUE %L',v_metodo_type,'airbnb');
  END IF;
END;
$;

-- Pago Airbnb idempotente posterior a la creación y al guardado del
-- estacionamiento. Así, si fallan las fechas de estacionamiento, la
-- reserva puede revertirse sin que un pago recién creado bloquee el DELETE.
CREATE OR REPLACE FUNCTION public.registrar_pago_airbnb(p_reserva_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  r public.reservas%rowtype;
  v_rol text;
  v_total_estadia integer;
  v_transaccion text;
  v_pago_id uuid;
  v_metodo_type regtype;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Sesión no válida';
  END IF;

  SELECT rr.* INTO r
  FROM public.reservas rr
  WHERE rr.id = p_reserva_id
  FOR UPDATE;

  IF NOT FOUND THEN RAISE EXCEPTION 'Reserva no encontrada'; END IF;
  IF lower(r.canal::text) <> 'airbnb' THEN
    RAISE EXCEPTION 'El pago automático solo aplica a reservas Airbnb';
  END IF;
  IF NULLIF(trim(COALESCE(r.referencia_externa,'')),'') IS NULL THEN
    RAISE EXCEPTION 'La reserva Airbnb debe tener código externo';
  END IF;

  SELECT lower(p.rol::text) INTO v_rol
  FROM public.perfiles p
  WHERE p.id = auth.uid() AND p.activo = true;

  IF v_rol IS NULL THEN RAISE EXCEPTION 'Usuario sin perfil activo'; END IF;
  IF r.creado_por IS DISTINCT FROM auth.uid()
     AND v_rol NOT IN ('gerencia','sysadmin','system_admin','systemadmin')
  THEN
    RAISE EXCEPTION 'Solo quien creó la reserva o Gerencia+ puede registrar su pago Airbnb';
  END IF;

  v_transaccion := 'AIRBNB-' || trim(r.referencia_externa);

  -- Un reintento devuelve el pago existente, no genera otro.
  SELECT p.id INTO v_pago_id
  FROM public.pagos p
  WHERE p.reserva_id = r.id
    AND p.id_transaccion = v_transaccion
  ORDER BY p.pagado_en DESC
  LIMIT 1;

  IF v_pago_id IS NOT NULL THEN
    RETURN v_pago_id;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.pagos p
    WHERE p.id_transaccion = v_transaccion
      AND p.reserva_id <> r.id
  ) THEN
    RAISE EXCEPTION 'El código de transacción Airbnb ya está asociado a otra reserva';
  END IF;

  v_total_estadia := greatest(
    0,
    (r.fecha_salida - r.fecha_entrada) * COALESCE(r.tarifa_noche,0)
  );
  IF v_total_estadia <= 0 THEN
    RAISE EXCEPTION 'El total de estadía Airbnb debe ser mayor que cero para registrar el pago automático';
  END IF;

  SELECT a.atttypid::regtype INTO v_metodo_type
  FROM pg_attribute a
  WHERE a.attrelid = 'public.pagos'::regclass
    AND a.attname = 'metodo'
    AND NOT a.attisdropped;
  IF v_metodo_type IS NULL THEN
    RAISE EXCEPTION 'No se pudo determinar el tipo del método de pago';
  END IF;

  EXECUTE format(
    'INSERT INTO public.pagos(
       reserva_id, metodo, moneda, monto_original, tipo_cambio,
       monto_clp, anticipado, motivo, id_transaccion, referencia, creado_por
     )
     VALUES ($1, $2::%s, $3::bpchar, $4, NULL, $4, true, $5, $6, $7, $8)
     RETURNING id',
    v_metodo_type
  )
  USING
    r.id, 'airbnb', 'CLP', v_total_estadia, 'estadia',
    v_transaccion, 'Pago procesado por Airbnb', auth.uid()
  INTO v_pago_id;

  INSERT INTO public.pagos_motivos(pago_id,motivo,monto_original,monto_clp)
  VALUES (v_pago_id,'estadia',v_total_estadia,v_total_estadia);

  RETURN v_pago_id;
END;
$$;

REVOKE ALL ON FUNCTION public.registrar_pago_airbnb(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.registrar_pago_airbnb(uuid) TO authenticated;

NOTIFY pgrst, 'reload schema';

COMMIT;

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

-- Reserva + pago Airbnb quedan en una única transacción.
-- El pago corresponde solo a estadía; cargos extra/estacionamiento
-- siguen separados. Se evita registrar pagos de monto cero.
CREATE OR REPLACE FUNCTION public.crear_reserva_con_reacomodacion(
  p_reserva jsonb,
  p_plan jsonb DEFAULT '[]'::jsonb,
  p_iva integer DEFAULT 0,
  p_otro integer DEFAULT 0
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  x jsonb;
  r public.reservas%rowtype;
  v_id uuid;
  v_pago_id uuid;
  v_metodo_type regtype;
  v_total_estadia integer;
  v_transaccion text;
BEGIN
  IF lower(COALESCE(p_reserva->>'canal','')) = 'airbnb'
     AND NULLIF(trim(COALESCE(p_reserva->>'referencia_externa','')),'') IS NULL
  THEN
    RAISE EXCEPTION 'El código externo es obligatorio para Airbnb para registrar su pago automáticamente';
  END IF;

  IF p_plan IS NOT NULL AND jsonb_typeof(p_plan) = 'array' THEN
    FOR x IN
      SELECT value FROM jsonb_array_elements(p_plan)
      ORDER BY (value->>'profundidad')::integer DESC
    LOOP
      SELECT * INTO r FROM public.reservas
      WHERE id = (x->>'reserva_id')::uuid FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'Reserva del plan no encontrada'; END IF;
      IF r.estado = 'en_casa' THEN RAISE EXCEPTION 'No se puede mover una reserva que está en casa'; END IF;
      IF r.estado = 'bloqueado' THEN RAISE EXCEPTION 'Un bloqueo de unidad no puede ser movido automáticamente'; END IF;
      IF COALESCE(r.no_mover_unidad,false) THEN
        RAISE EXCEPTION 'La reserva % está marcada para no mover de unidad', r.uid_reserva;
      END IF;
      IF EXISTS (
        SELECT 1 FROM public.reservas q
        WHERE q.unidad_id = (x->>'unidad_destino')::uuid
          AND q.id <> r.id
          AND q.fecha_entrada < r.fecha_salida
          AND q.fecha_salida > r.fecha_entrada
          AND q.estado NOT IN ('cancelada','no_show')
      ) THEN
        RAISE EXCEPTION 'La cadena ya no es válida: destino ocupado';
      END IF;
      UPDATE public.reservas
         SET unidad_id = (x->>'unidad_destino')::uuid, actualizado_en = now()
       WHERE id = r.id;
    END LOOP;
  END IF;

  INSERT INTO public.reservas(
    huesped_id, unidad_id, fecha_entrada, fecha_salida, estado,
    canal, referencia_externa, adultos, menores, tarifa_noche,
    usa_estacionamiento, noches_estacionamiento, modelo_vehiculo,
    patente_vehiculo, no_mover_unidad
  )
  VALUES (
    (p_reserva->>'huesped_id')::uuid,
    (p_reserva->>'unidad_id')::uuid,
    (p_reserva->>'fecha_entrada')::date,
    (p_reserva->>'fecha_salida')::date,
    (p_reserva->>'estado')::estado_reserva,
    (p_reserva->>'canal')::canal_reserva,
    NULLIF(trim(p_reserva->>'referencia_externa'),''),
    COALESCE((p_reserva->>'adultos')::integer,1),
    COALESCE((p_reserva->>'menores')::integer,0),
    COALESCE((p_reserva->>'tarifa_noche')::integer,0),
    COALESCE((p_reserva->>'usa_estacionamiento')::boolean,false),
    COALESCE((p_reserva->>'noches_estacionamiento')::integer,0),
    NULLIF(trim(p_reserva->>'modelo_vehiculo'),''),
    NULLIF(trim(p_reserva->>'patente_vehiculo'),''),
    COALESCE((p_reserva->>'no_mover_unidad')::boolean,false)
  )
  RETURNING id INTO v_id;

  IF COALESCE(p_iva,0) <> 0 THEN
    INSERT INTO public.cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario)
    VALUES (v_id,'otro','__PMS_IVA__',1,p_iva);
  END IF;
  IF COALESCE(p_otro,0) <> 0 THEN
    INSERT INTO public.cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario)
    VALUES (v_id,'otro','__PMS_OTRO_PRECIO__',1,p_otro);
  END IF;

  IF lower(COALESCE(p_reserva->>'canal','')) = 'airbnb' THEN
    v_transaccion := 'AIRBNB-' || trim(p_reserva->>'referencia_externa');
    v_total_estadia := greatest(
      0,
      ((p_reserva->>'fecha_salida')::date - (p_reserva->>'fecha_entrada')::date)
      * COALESCE((p_reserva->>'tarifa_noche')::integer,0)
    );

    IF v_total_estadia > 0 THEN
      SELECT a.atttypid::regtype INTO v_metodo_type
      FROM pg_attribute a
      WHERE a.attrelid = 'public.pagos'::regclass
        AND a.attname = 'metodo' AND NOT a.attisdropped;
      IF v_metodo_type IS NULL THEN RAISE EXCEPTION 'No se pudo determinar el tipo del método de pago'; END IF;

      EXECUTE format(
        'INSERT INTO public.pagos(
           reserva_id, metodo, moneda, monto_original, tipo_cambio,
           monto_clp, anticipado, motivo, id_transaccion, referencia, creado_por
         )
         VALUES ($1, $2::%s, $3::bpchar, $4, NULL, $4, true, $5, $6, $7, $8)
         RETURNING id',
        v_metodo_type
      )
      USING v_id, 'webpay', 'CLP', v_total_estadia, 'estadia',
            v_transaccion, 'Pago procesado por Airbnb', auth.uid()
      INTO v_pago_id;

      INSERT INTO public.pagos_motivos(pago_id,motivo,monto_original,monto_clp)
      VALUES (v_pago_id,'estadia',v_total_estadia,v_total_estadia);
    END IF;
  END IF;

  RETURN v_id;
END;
$$;

NOTIFY pgrst, 'reload schema';

COMMIT;

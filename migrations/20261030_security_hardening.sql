-- Security hardening migration for MMassisT PMS (2026-10-30).
-- Apply after the base schema. The two public policy RPCs are the only
-- anonymous SECURITY DEFINER endpoints; their codes are 128-bit random tokens.
BEGIN;

REVOKE ALL PRIVILEGES ON TABLE
 public.buzon_conversacion_miembros,public.buzon_conversaciones,public.catalogo_unidades,
 public.estado_limpieza_actual,public.garantia_reserva,public.pagos_compartidos,
 public.pagos_compartidos_distribucion,public.reserva_grupo_miembros,public.reserva_grupos,
 public.resumen_huesped,public.saldo_reserva
FROM anon;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
 REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER TABLE public.politicas_links
 ALTER COLUMN codigo TYPE text USING upper(btrim(codigo::text));
UPDATE public.politicas_links
 SET activo=false
 WHERE activo=true AND aceptado_en IS NULL AND codigo !~ '^[0-9A-F]{32}$';

CREATE OR REPLACE FUNCTION public.revisar_lista_negra_huesped(p_huesped_id uuid)
 RETURNS TABLE(id uuid, nombre_completo text, tipo_documento text, numero_documento text, documento_normalizado text, motivo text, activo boolean)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select
    l.id,
    l.nombre_completo,
    l.tipo_documento,
    l.numero_documento,
    l.documento_normalizado,
    l.motivo,
    l.activo
  from public.huespedes h
  join public.lista_negra l
    on l.activo = true
   and (
      (
        nullif(trim(h.documento_normalizado),'') is not null
        and nullif(trim(l.documento_normalizado),'') is not null
        and h.documento_normalizado = l.documento_normalizado
      )
      or (
        nullif(trim(h.numero_documento),'') is not null
        and nullif(trim(l.numero_documento),'') is not null
        and lower(trim(h.numero_documento)) = lower(trim(l.numero_documento))
      )
      or (
        nullif(trim(h.documento_normalizado),'') is null
        and nullif(trim(h.numero_documento),'') is null
        and public.normalizar_nombre_lista_negra(h.nombre_completo)
            = public.normalizar_nombre_lista_negra(l.nombre_completo)
      )
    )
  where h.id = p_huesped_id AND public.pms_rol() IN ('recepcion','administracion','gerencia','sysadmin') AND EXISTS (SELECT 1 FROM public.reservas r JOIN public.unidades u ON u.id=r.unidad_id WHERE r.huesped_id=h.id AND public.puede_ver_edificio(u.edificio_id));
$function$;

CREATE OR REPLACE FUNCTION public.revisar_lista_negra(p_documento text DEFAULT NULL::text, p_nombre text DEFAULT NULL::text)
 RETURNS TABLE(id uuid, nombre_completo text, motivo text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select l.id,l.nombre_completo,l.motivo
  from public.lista_negra l
  where l.activo = true AND public.pms_rol() IN ('recepcion','administracion','gerencia','sysadmin')
    and (
      (
        nullif(trim(p_documento),'') is not null
        and nullif(trim(l.documento_normalizado),'') is not null
        and l.documento_normalizado =
            regexp_replace(lower(trim(p_documento)),'[^a-z0-9]','','g')
      )
      or (
        nullif(trim(p_documento),'') is null
        and public.normalizar_nombre_lista_negra(l.nombre_completo)
            = public.normalizar_nombre_lista_negra(p_nombre)
      )
    )
  order by l.agregado_en desc;
$function$;

CREATE OR REPLACE FUNCTION public.buscar_extension_estadia(p_reserva_id uuid, p_nueva_entrada date, p_nueva_salida date)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_temp', 'public'
AS $function$
DECLARE
  r reservas%rowtype;
  v_blocker reservas%rowtype;
  v_plan jsonb;
  v_count integer;
BEGIN
  IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RAISE EXCEPTION 'Sesión o rol no autorizado'; END IF;
  SELECT *
  INTO r
  FROM public.reservas rr
  WHERE rr.id = p_reserva_id;

  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'Reserva no encontrada'
    );
  END IF;

  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id = r.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF r.estado IN ('cancelada','no_show','bloqueado','check_out') THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'Esta reserva no puede extenderse en su estado actual'
    );
  END IF;

  IF p_nueva_entrada >= r.fecha_entrada
     AND p_nueva_salida <= r.fecha_salida
  THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'Las nuevas fechas no amplían la estadía'
    );
  END IF;

  IF p_nueva_entrada > r.fecha_entrada
     OR p_nueva_salida < r.fecha_salida
  THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'Una extensión no puede reducir ninguno de los extremos actuales'
    );
  END IF;

  IF p_nueva_salida <= p_nueva_entrada THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'La salida debe ser posterior a la entrada'
    );
  END IF;

  IF p_nueva_entrada < r.fecha_entrada
     AND r.estado = 'en_casa'
  THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'No se puede ampliar hacia atrás una estadía que ya está en casa'
    );
  END IF;

  /*
   * Si la nueva entrada queda en el pasado respecto del inicio actual
   * y la reserva ya comenzó, tampoco permitimos retroactividad.
   */
  IF p_nueva_entrada < r.fecha_entrada
     AND r.fecha_entrada < CURRENT_DATE
  THEN
    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'La fecha de entrada actual ya quedó en el pasado'
    );
  END IF;

  DROP TABLE IF EXISTS pms_extension_plan;

  CREATE TEMP TABLE pms_extension_plan (
    reserva_id uuid PRIMARY KEY,
    unidad_origen uuid NOT NULL,
    unidad_destino uuid NOT NULL,
    profundidad integer NOT NULL,
    fecha_entrada date NOT NULL,
    fecha_salida date NOT NULL
  ) ON COMMIT DROP;


  /*
   * Buscar todas las reservas que actualmente bloquean cualquier parte
   * del nuevo intervalo en la unidad original.
   */
  IF EXISTS (
    SELECT 1
    FROM public.reservas q
    WHERE q.unidad_id = r.unidad_id
      AND q.id <> r.id
      AND q.fecha_entrada < p_nueva_salida
      AND q.fecha_salida > p_nueva_entrada
      AND q.estado NOT IN ('cancelada','no_show')
      AND (
        q.estado IN ('en_casa','bloqueado')
        OR COALESCE(q.no_mover_unidad,false)
      )
  ) THEN
    SELECT q.*
    INTO v_blocker
    FROM public.reservas q
    WHERE q.unidad_id = r.unidad_id
      AND q.id <> r.id
      AND q.fecha_entrada < p_nueva_salida
      AND q.fecha_salida > p_nueva_entrada
      AND q.estado NOT IN ('cancelada','no_show')
      AND (
        q.estado IN ('en_casa','bloqueado')
        OR COALESCE(q.no_mover_unidad,false)
      )
    ORDER BY q.fecha_entrada
    LIMIT 1;

    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'La unidad actual tiene una reserva o bloqueo que no puede ser reacomodado',
      'bloqueador', v_blocker.id
    );
  END IF;


  /*
   * Planificar cada blocker del nuevo intervalo.
   */
  FOR v_blocker IN
    SELECT q.*
    FROM public.reservas q
    WHERE q.unidad_id = r.unidad_id
      AND q.id <> r.id
      AND q.fecha_entrada < p_nueva_salida
      AND q.fecha_salida > p_nueva_entrada
      AND q.estado NOT IN ('cancelada','no_show')
    ORDER BY q.fecha_entrada, q.fecha_salida, q.id
  LOOP

    IF NOT public.pms_plan_extension_move(
      v_blocker.id,
      r.unidad_id,
      1,
      ARRAY[r.id]::uuid[],
      ARRAY[r.unidad_id]::uuid[]
    ) THEN

      DROP TABLE IF EXISTS pms_extension_plan;

      RETURN jsonb_build_object(
        'posible', false,
        'razon', 'No existe una reacomodación completa para liberar la unidad durante toda la extensión'
      );

    END IF;

  END LOOP;


  /*
   * Validación final del intervalo completo.
   *
   * El único ocupante permitido en la unidad original durante las
   * nuevas fechas debe ser la propia reserva principal. Todos los
   * demás ocupantes deben formar parte del plan.
   */
  IF EXISTS (
    SELECT 1
    FROM public.reservas q
    WHERE q.unidad_id = r.unidad_id
      AND q.id <> r.id
      AND q.fecha_entrada < p_nueva_salida
      AND q.fecha_salida > p_nueva_entrada
      AND q.estado NOT IN ('cancelada','no_show')
      AND NOT EXISTS (
        SELECT 1
        FROM pms_extension_plan p
        WHERE p.reserva_id = q.id
      )
  ) THEN

    DROP TABLE IF EXISTS pms_extension_plan;

    RETURN jsonb_build_object(
      'posible', false,
      'razon', 'La unidad actual no puede quedar libre durante toda la extensión'
    );

  END IF;


  SELECT
    COALESCE(
      jsonb_agg(
        jsonb_build_object(
          'reserva_id', reserva_id,
          'unidad_origen', unidad_origen,
          'unidad_destino', unidad_destino,
          'profundidad', profundidad,
          'fecha_entrada', fecha_entrada,
          'fecha_salida', fecha_salida
        )
        ORDER BY profundidad DESC, fecha_entrada, reserva_id
      ),
      '[]'::jsonb
    ),
    count(*)
  INTO v_plan, v_count
  FROM pms_extension_plan;


  RETURN jsonb_build_object(
    'posible', true,
    'reserva_id', r.id,
    'unidad_id', r.unidad_id,
    'nueva_entrada', p_nueva_entrada,
    'nueva_salida', p_nueva_salida,
    'noches_nuevas', p_nueva_salida - p_nueva_entrada,
    'reacomodaciones', v_count,
    'plan', v_plan
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.registrar_pago_completo(p_reserva_id uuid, p_metodo text, p_moneda text, p_monto_original numeric, p_tipo_cambio numeric, p_monto_clp integer, p_anticipado boolean, p_motivo_principal text, p_id_transaccion text, p_motivos jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_pago_id uuid;

  v_sum_original numeric := 0;
  v_sum_clp integer := 0;

  v_item jsonb;
  v_motivo text;
  v_orig numeric;
  v_clp integer;

  v_metodo_type regtype;
BEGIN

  -- ==========================================================
  -- VALIDACIÓN DE SESIÓN
  -- ==========================================================

  IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión o rol no autorizado';
  END IF;


  -- ==========================================================
  -- VALIDACIÓN DE RESERVA
  -- ==========================================================

  IF NOT EXISTS (
    SELECT 1 FROM public.reservas r JOIN public.unidades u ON u.id = r.unidad_id
    WHERE r.id = p_reserva_id AND public.puede_ver_edificio(u.edificio_id)
  ) THEN
    RAISE EXCEPTION 'Reserva no disponible para este usuario';
  END IF;


  -- ==========================================================
  -- VALIDACIÓN DEL MONTO
  -- ==========================================================

  IF p_monto_original IS NULL
     OR p_monto_original <= 0
     OR p_monto_clp IS NULL
     OR p_monto_clp <= 0
  THEN
    RAISE EXCEPTION 'El monto del pago debe ser mayor que cero';
  END IF;


  -- ==========================================================
  -- VALIDACIÓN DEL MOTIVO PRINCIPAL
  -- ==========================================================

  IF p_motivo_principal NOT IN (
    'estadia',
    'estacionamiento',
    'horario_extra',
    'penalizacion',
    'consumos',
    'garantia',
    'otro'
  ) THEN
    RAISE EXCEPTION 'Motivo de pago no válido';
  END IF;


  -- ==========================================================
  -- VALIDACIÓN DEL ARRAY DE MOTIVOS
  -- ==========================================================

  IF p_motivos IS NULL
     OR jsonb_typeof(p_motivos) <> 'array'
     OR jsonb_array_length(p_motivos) = 0
  THEN
    RAISE EXCEPTION 'El pago debe tener al menos un motivo';
  END IF;


  -- ==========================================================
  -- VALIDAR Y SUMAR MOTIVOS
  -- ==========================================================

  FOR v_item IN
    SELECT value
    FROM jsonb_array_elements(p_motivos)
  LOOP

    v_motivo := v_item->>'motivo';

    v_orig :=
      (v_item->>'monto_original')::numeric;

    v_clp :=
      (v_item->>'monto_clp')::integer;


    IF v_motivo NOT IN (
      'estadia',
      'estacionamiento',
      'horario_extra',
      'penalizacion',
      'consumos',
      'garantia',
      'otro'
    ) THEN
      RAISE EXCEPTION
        'Motivo de pago no válido: %',
        v_motivo;
    END IF;


    IF v_orig IS NULL
       OR v_orig <= 0
       OR v_clp IS NULL
       OR v_clp <= 0
    THEN
      RAISE EXCEPTION
        'Todos los motivos deben tener un monto mayor que cero';
    END IF;


    v_sum_original :=
      v_sum_original + v_orig;

    v_sum_clp :=
      v_sum_clp + v_clp;

  END LOOP;


  -- ==========================================================
  -- LOS MOTIVOS DEBEN SUMAR EL PAGO
  -- ==========================================================

  IF abs(
    v_sum_original - p_monto_original
  ) > 0.005
  THEN
    RAISE EXCEPTION
      'Los motivos no coinciden con el monto total del pago';
  END IF;


  IF abs(
    v_sum_clp - p_monto_clp
  ) > 1
  THEN
    RAISE EXCEPTION
      'Los motivos en CLP no coinciden con el monto total del pago';
  END IF;


  -- ==========================================================
  -- OBTENER TIPO REAL DE LA COLUMNA metodo
  --
  -- No asumimos el nombre del ENUM existente.
  -- ==========================================================

  SELECT a.atttypid::regtype
  INTO v_metodo_type
  FROM pg_attribute a
  WHERE a.attrelid = 'public.pagos'::regclass
    AND a.attname = 'metodo'
    AND NOT a.attisdropped;


  IF v_metodo_type IS NULL THEN
    RAISE EXCEPTION
      'No se pudo determinar el tipo de método de pago';
  END IF;


  -- ==========================================================
  -- CREAR PAGO
  --
  -- SECURITY DEFINER permite que esta operación se realice
  -- de forma controlada sin exponer INSERT directo sobre
  -- pagos_motivos al cliente.
  -- ==========================================================

  EXECUTE format(
    '
    INSERT INTO public.pagos(
      reserva_id,
      metodo,
      moneda,
      monto_original,
      tipo_cambio,
      monto_clp,
      anticipado,
      motivo,
      id_transaccion,
      creado_por
    )
    VALUES (
      $1,
      $2::%s,
      $3::bpchar,
      $4,
      $5,
      $6,
      $7,
      $8,
      $9,
      $10
    )
    RETURNING id
    ',
    v_metodo_type
  )
  USING
    p_reserva_id,
    p_metodo,
    p_moneda,
    p_monto_original,
    p_tipo_cambio,
    p_monto_clp,
    COALESCE(p_anticipado, false),
    p_motivo_principal,
    NULLIF(
      trim(p_id_transaccion),
      ''
    ),
    auth.uid()
  INTO v_pago_id;


  -- ==========================================================
  -- CREAR TODOS LOS MOTIVOS DEL PAGO
  -- ==========================================================

  FOR v_item IN
    SELECT value
    FROM jsonb_array_elements(p_motivos)
  LOOP

    INSERT INTO public.pagos_motivos(
      pago_id,
      motivo,
      monto_original,
      monto_clp
    )
    VALUES (
      v_pago_id,
      v_item->>'motivo',
      (v_item->>'monto_original')::numeric,
      (v_item->>'monto_clp')::integer
    );

  END LOOP;


  -- ==========================================================
  -- DEVOLVER ID DEL PAGO
  -- ==========================================================

  RETURN v_pago_id;

END;
$function$;

CREATE OR REPLACE FUNCTION public.editar_reserva_completa(p_reserva_id uuid, p_huesped_nombre text DEFAULT NULL::text, p_tipo_documento text DEFAULT NULL::text, p_numero_documento text DEFAULT NULL::text, p_telefono text DEFAULT NULL::text, p_correo text DEFAULT NULL::text, p_nacionalidad text DEFAULT NULL::text, p_ciudad_origen text DEFAULT NULL::text, p_estado text DEFAULT NULL::text, p_fecha_entrada date DEFAULT NULL::date, p_fecha_salida date DEFAULT NULL::date, p_unidad_id uuid DEFAULT NULL::uuid, p_canal text DEFAULT NULL::text, p_referencia_externa text DEFAULT NULL::text, p_adultos integer DEFAULT NULL::integer, p_menores integer DEFAULT NULL::integer, p_tarifa_noche integer DEFAULT NULL::integer, p_total_manual integer DEFAULT NULL::integer, p_modelo_vehiculo text DEFAULT NULL::text, p_patente_vehiculo text DEFAULT NULL::text, p_cupo_estacionamiento integer DEFAULT NULL::integer, p_usa_estacionamiento boolean DEFAULT NULL::boolean, p_observaciones text DEFAULT NULL::text, p_iva_total integer DEFAULT NULL::integer, p_otro_precio integer DEFAULT NULL::integer, p_noches_estacionamiento integer DEFAULT NULL::integer)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  r reservas%rowtype;
  v_user uuid := auth.uid();
  v_ent date;
  v_sal date;
  v_unit uuid;
  v_iva integer;
  v_otro integer;
  v_npark integer;
  v_base_total integer;
  v_ajuste integer;
  v_rol text;
  v_editor_privilegiado boolean := false;
begin
  select * into r from reservas where id = p_reserva_id for update;
  if not found then raise exception 'Reserva no encontrada'; end if;
  if v_user is null then raise exception 'Sesión no válida'; end if;

  SELECT lower(
           regexp_replace(
             trim(coalesce(p.rol::text,'')),
             '[\s-]+',
             '_',
             'g'
           )
         )
    INTO v_rol
    FROM public.perfiles p
   WHERE p.id = v_user;

  v_editor_privilegiado := coalesce(
    v_rol IN (
      'recepcion',
      'administracion',
      'gerencia',
      'sysadmin',
      'system_admin',
      'systemadmin'
    ),
    false
  );

  IF coalesce(v_rol, '') NOT IN ('recepcion','administracion','gerencia','sysadmin','system_admin','systemadmin') THEN RAISE EXCEPTION 'No autorizado'; END IF;
  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id = r.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF p_unidad_id IS NOT NULL AND NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id = p_unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a la unidad destino'; END IF;
  v_ent := coalesce(p_fecha_entrada,r.fecha_entrada);
  v_sal := coalesce(p_fecha_salida,r.fecha_salida);
  v_unit := coalesce(p_unidad_id,r.unidad_id);
  v_iva := greatest(0,coalesce(p_iva_total,0));
  v_otro := greatest(0,coalesce(p_otro_precio,0));
  v_npark := greatest(0,coalesce(p_noches_estacionamiento,r.noches_estacionamiento,
    case when r.usa_estacionamiento then (r.fecha_salida-r.fecha_entrada) else 0 end));

  if v_sal <= v_ent then raise exception 'La salida debe ser posterior a la entrada'; end if;
  if p_canal is not null and p_canal='booking' and nullif(trim(coalesce(p_referencia_externa,'')),'') is null
     and public.tiene_permiso_edicion(v_user,'channel')
  then raise exception 'El código externo es obligatorio para Booking'; end if;
  if v_npark > (v_sal-v_ent) then raise exception 'Las noches con estacionamiento no pueden superar la estadía'; end if;
  if r.estado='en_casa' and v_unit<>r.unidad_id then raise exception 'Una persona que ya está en casa nunca puede ser movida de unidad'; end if;

  if p_huesped_nombre is not null and (v_editor_privilegiado or public.tiene_permiso_edicion(v_user,'guest_name')) then
    update huespedes set nombre_completo=p_huesped_nombre where id=r.huesped_id;
    update reservas set huesped_nombre_copia=p_huesped_nombre where id=r.id;
  end if;
  -- El botón universal de Guardar Cambios debe permitir que Recepción y los perfiles administrativos guarden los datos documentales del huésped aunque no tengan un registro individual de permisos de edición. Esto evita que el campo se revierta al recargar la reserva.
  if v_editor_privilegiado
     or public.tiene_permiso_edicion(v_user,'guest_document') then
    update huespedes
      set tipo_documento=coalesce(nullif(trim(p_tipo_documento),''),tipo_documento),
          numero_documento=coalesce(nullif(trim(p_numero_documento),''),numero_documento)
      where id=r.huesped_id;
  end if;
  if v_editor_privilegiado or public.tiene_permiso_edicion(v_user,'guest_contact') then
    update huespedes set telefono=coalesce(p_telefono,telefono),correo=coalesce(p_correo,correo),nacionalidad=coalesce(p_nacionalidad,nacionalidad),ciudad_origen=coalesce(p_ciudad_origen,ciudad_origen) where id=r.huesped_id;
  end if;
  if p_estado is not null and public.tiene_permiso_edicion(v_user,'status') then
    update reservas set estado=p_estado::estado_reserva where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'channel') then
    -- FIX: ambos argumentos de COALESCE deben ser canal_reserva.
    update reservas
      set canal=coalesce(p_canal::canal_reserva,canal),
          referencia_externa=case when p_referencia_externa is null then referencia_externa else nullif(trim(p_referencia_externa),'') end
      where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'occupancy') then
    update reservas set adultos=coalesce(p_adultos,adultos),menores=coalesce(p_menores,menores) where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'rate') then
    update reservas set tarifa_noche=coalesce(p_tarifa_noche,tarifa_noche) where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'vehicle') then
    if coalesce(p_usa_estacionamiento,r.usa_estacionamiento)
       and nullif(trim(coalesce(p_modelo_vehiculo,r.modelo_vehiculo,'')),'') is null
       then raise exception 'Para usar estacionamiento debes indicar el modelo del vehículo'; end if;
    if coalesce(p_usa_estacionamiento,r.usa_estacionamiento)
       and nullif(trim(coalesce(p_patente_vehiculo,r.patente_vehiculo,'')),'') is null
       then raise exception 'Para usar estacionamiento debes indicar la patente del vehículo'; end if;
    update reservas set modelo_vehiculo=coalesce(nullif(trim(p_modelo_vehiculo),''),modelo_vehiculo),patente_vehiculo=coalesce(nullif(trim(p_patente_vehiculo),''),patente_vehiculo),cupo_estacionamiento=p_cupo_estacionamiento,usa_estacionamiento=coalesce(p_usa_estacionamiento,usa_estacionamiento) where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'observations') then
    update reservas set observaciones=p_observaciones where id=r.id;
  end if;
  if public.tiene_permiso_edicion(v_user,'dates') or public.tiene_permiso_edicion(v_user,'building_category_unit') then
    if public.tiene_permiso_edicion(v_user,'dates') or public.tiene_permiso_edicion(v_user,'building_category_unit') then
      if r.estado='en_casa' and v_unit<>r.unidad_id then raise exception 'Una persona que ya está en casa nunca puede ser movida de unidad'; end if;
      if exists(select 1 from reservas x where x.id<>r.id and x.unidad_id=v_unit and x.estado in ('tentativa','confirmada','en_casa','bloqueado') and x.fecha_entrada<v_sal and x.fecha_salida>v_ent) then raise exception 'La unidad ya está ocupada en esas fechas'; end if;
      update reservas set unidad_id=v_unit,fecha_entrada=v_ent,fecha_salida=v_sal where id=r.id;
    end if;
  end if;

  if public.tiene_permiso_edicion(v_user,'price_iva') then
    delete from cargos where reserva_id=r.id and descripcion='__PMS_IVA__';
    if v_iva>0 then insert into cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario) values(r.id,'otro','__PMS_IVA__',1,v_iva); end if;
  end if;
  if public.tiene_permiso_edicion(v_user,'price_other') then
    delete from cargos where reserva_id=r.id and descripcion='__PMS_OTRO_PRECIO__';
    if v_otro>0 then insert into cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario) values(r.id,'otro','__PMS_OTRO_PRECIO__',1,v_otro); end if;
  end if;
  if public.tiene_permiso_edicion(v_user,'parking_nights') then
    update reservas set noches_estacionamiento=case when coalesce(p_usa_estacionamiento,r.usa_estacionamiento) then v_npark else 0 end where id=r.id;
  end if;

  if p_total_manual is not null and public.tiene_permiso_edicion(v_user,'total') then
    -- El total manual corresponde exclusivamente a la estadía.
    -- Los cargos extra nunca se suman al total base ni generan ajustes
    -- negativos para compensarlos. Se eliminan ajustes antiguos al guardar.
    delete from cargos
     where reserva_id=r.id
       and tipo='otro'
       and descripcion='__PMS_AJUSTE_TOTAL_MANUAL__';

    select (v_sal-v_ent) * coalesce(
      (select tarifa_noche from reservas where id=r.id),
      r.tarifa_noche
    )
      into v_base_total;

    -- Solo se conserva un ajuste cuando el total manual difiere del
    -- total de noches × tarifa; los cargos extra quedan completamente aparte.
    v_ajuste := p_total_manual - coalesce(v_base_total,0);
    if v_ajuste > 0 then
      insert into cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario)
      values(r.id,'otro','__PMS_AJUSTE_TOTAL_MANUAL__',1,v_ajuste);
    end if;
  end if;
end;
$function$;

CREATE OR REPLACE FUNCTION public.crear_reserva_con_reacomodacion(p_reserva jsonb, p_plan jsonb DEFAULT '[]'::jsonb, p_iva integer DEFAULT 0, p_otro integer DEFAULT 0)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE x jsonb; r reservas%rowtype; v_id uuid;
BEGIN
 IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RAISE EXCEPTION 'Sesión o rol no autorizado'; END IF;
 IF NOT EXISTS (SELECT 1 FROM public.unidades u WHERE u.id = (p_reserva->>'unidad_id')::uuid AND public.puede_ver_edificio(u.edificio_id)) THEN RAISE EXCEPTION 'No tienes acceso a la unidad solicitada'; END IF;
 IF p_plan IS NOT NULL AND jsonb_typeof(p_plan)='array' THEN
  FOR x IN SELECT value FROM jsonb_array_elements(p_plan) ORDER BY (value->>'profundidad')::int DESC LOOP
   SELECT * INTO r FROM reservas WHERE id=(x->>'reserva_id')::uuid FOR UPDATE;
   IF NOT FOUND THEN RAISE EXCEPTION 'Reserva del plan no encontrada'; END IF;
   IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=r.unidad_id)) OR NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=(x->>'unidad_destino')::uuid)) THEN RAISE EXCEPTION 'No tienes acceso a esta reacomodación'; END IF;
   IF r.estado='en_casa' THEN RAISE EXCEPTION 'No se puede mover una reserva que está en casa'; END IF;
   IF r.estado='bloqueado' THEN RAISE EXCEPTION 'Un bloqueo de unidad no puede ser movido automáticamente'; END IF;
   IF COALESCE(r.no_mover_unidad,false) THEN RAISE EXCEPTION 'La reserva % está marcada para no mover de unidad',r.uid_reserva; END IF;
   IF EXISTS(SELECT 1 FROM reservas q WHERE q.unidad_id=(x->>'unidad_destino')::uuid AND q.id<>r.id AND q.fecha_entrada<r.fecha_salida AND q.fecha_salida>r.fecha_entrada AND q.estado NOT IN ('cancelada','no_show')) THEN
    RAISE EXCEPTION 'La cadena ya no es válida: destino ocupado';
   END IF;
   UPDATE reservas SET unidad_id=(x->>'unidad_destino')::uuid,actualizado_en=now() WHERE id=r.id;
  END LOOP;
 END IF;
 INSERT INTO reservas(
  huesped_id,unidad_id,fecha_entrada,fecha_salida,estado,canal,referencia_externa,
  adultos,menores,tarifa_noche,usa_estacionamiento,noches_estacionamiento,
  modelo_vehiculo,patente_vehiculo,no_mover_unidad,hora_llegada_aprox,hora_salida_aprox,observaciones
 )
 VALUES(
  (p_reserva->>'huesped_id')::uuid,(p_reserva->>'unidad_id')::uuid,
  (p_reserva->>'fecha_entrada')::date,(p_reserva->>'fecha_salida')::date,
  (p_reserva->>'estado')::estado_reserva,(p_reserva->>'canal')::canal_reserva,
  NULLIF(p_reserva->>'referencia_externa',''),
  COALESCE((p_reserva->>'adultos')::int,1),COALESCE((p_reserva->>'menores')::int,0),
  COALESCE((p_reserva->>'tarifa_noche')::int,0),COALESCE((p_reserva->>'usa_estacionamiento')::boolean,false),
  COALESCE((p_reserva->>'noches_estacionamiento')::int,0),NULLIF(p_reserva->>'modelo_vehiculo',''),
  NULLIF(p_reserva->>'patente_vehiculo',''),COALESCE((p_reserva->>'no_mover_unidad')::boolean,false),
  NULLIF(p_reserva->>'hora_llegada_aprox','')::time,NULLIF(p_reserva->>'hora_salida_aprox','')::time,
  NULLIF(p_reserva->>'observaciones','')
 ) RETURNING id INTO v_id;
 IF COALESCE(p_iva,0)<>0 THEN INSERT INTO cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario) VALUES(v_id,'otro','__PMS_IVA__',1,p_iva); END IF;
 IF COALESCE(p_otro,0)<>0 THEN INSERT INTO cargos(reserva_id,tipo,descripcion,cantidad,monto_unitario) VALUES(v_id,'otro','__PMS_OTRO_PRECIO__',1,p_otro); END IF;
 RETURN v_id;
END $function$;

CREATE OR REPLACE FUNCTION public.actualizar_limpieza(p_limpieza_id uuid, p_estado estado_limpieza, p_observacion text DEFAULT NULL::text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if rol_actual() is null then
    raise exception 'No autorizado';
  end if;
  if not exists (select 1 from public.limpieza l join public.unidades u on u.id=l.unidad_id where l.id=p_limpieza_id and public.puede_ver_edificio(u.edificio_id)) then raise exception 'No tienes acceso a esta unidad'; end if;
  if p_estado = 'defectuosa' and coalesce(trim(p_observacion), '') = '' then
    raise exception 'Indica el problema encontrado';
  end if;

  update limpieza
     set estado = p_estado,
         observacion_limpieza = coalesce(p_observacion, observacion_limpieza),
         iniciado_en  = case when p_estado = 'en_proceso' and iniciado_en is null then now() else iniciado_en end,
         terminado_en = case when p_estado in ('limpia','defectuosa') then now() else terminado_en end,
         asignado_a = coalesce(asignado_a, auth.uid()),
         actualizado_por = auth.uid()
   where id = p_limpieza_id;
end $function$;

CREATE OR REPLACE FUNCTION public.crear_reserva_grupal_completa(p_nombre_grupo text, p_reservas jsonb, p_pago jsonb DEFAULT NULL::jsonb, p_observaciones_grupo text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $function$
DECLARE
  v_grupo uuid; v_item jsonb; v_guest jsonb; v_reserva jsonb;
  v_huesped uuid; v_shared_huesped uuid; v_reserva_id uuid; v_pago_id uuid; v_pago_fila uuid;
  v_metodo metodo_pago; v_moneda char(3); v_tipo_cambio numeric;
  v_monto_original numeric; v_total_asignado integer := 0; v_total_pago integer := 0;
  v_fechas date[]; v_ids jsonb := '[]'::jsonb; v_idx integer := 0;
  v_alloc integer; v_perm_sobrecupo boolean;
BEGIN
  IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RAISE EXCEPTION 'Sesión o rol no autorizado para crear grupos'; END IF;
  IF jsonb_typeof(p_reservas) <> 'array' OR jsonb_array_length(p_reservas) < 2 OR jsonb_array_length(p_reservas) > 20 THEN
    RAISE EXCEPTION 'El grupo debe contener entre 2 y 20 reservas';
  END IF;

  FOR v_item IN SELECT value FROM jsonb_array_elements(p_reservas) LOOP
    v_reserva := v_item->'reserva';
    IF NULLIF(v_reserva->>'unidad_id','') IS NULL OR NULLIF(v_reserva->>'fecha_entrada','') IS NULL
       OR NULLIF(v_reserva->>'fecha_salida','') IS NULL
       OR (v_reserva->>'fecha_salida')::date <= (v_reserva->>'fecha_entrada')::date THEN
      RAISE EXCEPTION 'Una reserva del grupo tiene unidad o fechas inválidas';
    END IF;
    IF NULLIF(v_item->'huesped'->>'nombre_completo','') IS NULL THEN RAISE EXCEPTION 'Cada reserva debe tener un huésped principal'; END IF;
    IF NOT EXISTS (SELECT 1 FROM public.unidades u WHERE u.id=(v_reserva->>'unidad_id')::uuid AND public.puede_ver_edificio(u.edificio_id)) THEN RAISE EXCEPTION 'No tienes acceso a una unidad del grupo'; END IF;
    IF jsonb_typeof(COALESCE(v_item->'plan','[]'::jsonb))='array' AND EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(v_item->'plan','[]'::jsonb)) pl(value) JOIN public.reservas r0 ON r0.id=(pl.value->>'reserva_id')::uuid JOIN public.unidades u0 ON u0.id=r0.unidad_id LEFT JOIN public.unidades u1 ON u1.id=(pl.value->>'unidad_destino')::uuid WHERE NOT public.puede_ver_edificio(u0.edificio_id) OR u1.id IS NULL OR NOT public.puede_ver_edificio(u1.edificio_id)) THEN RAISE EXCEPTION 'No tienes acceso a una reacomodación del grupo'; END IF;
    IF COALESCE((v_reserva->>'usa_estacionamiento')::boolean,false)
       AND (NULLIF(v_reserva->>'modelo_vehiculo','') IS NULL OR NULLIF(v_reserva->>'patente_vehiculo','') IS NULL) THEN
      RAISE EXCEPTION 'Falta modelo o patente del vehículo en una reserva con estacionamiento';
    END IF;
    IF COALESCE(jsonb_array_length(COALESCE(v_item->'plan','[]'::jsonb)),0)=0 AND EXISTS (
      SELECT 1 FROM public.reservas r WHERE r.unidad_id=(v_reserva->>'unidad_id')::uuid
        AND r.estado NOT IN ('cancelada','no_show')
        AND r.fecha_entrada < (v_reserva->>'fecha_salida')::date
        AND r.fecha_salida > (v_reserva->>'fecha_entrada')::date
    ) THEN RAISE EXCEPTION 'Una unidad seleccionada está ocupada. No se guardó ninguna reserva del grupo.'; END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_reservas) WITH ORDINALITY a(value,ord)
    JOIN jsonb_array_elements(p_reservas) WITH ORDINALITY b(value,ord) ON b.ord>a.ord
    WHERE a.value->'reserva'->>'unidad_id'=b.value->'reserva'->>'unidad_id'
      AND (a.value->'reserva'->>'fecha_entrada')::date < (b.value->'reserva'->>'fecha_salida')::date
      AND (a.value->'reserva'->>'fecha_salida')::date > (b.value->'reserva'->>'fecha_entrada')::date
  ) THEN RAISE EXCEPTION 'Dos reservas del grupo se superponen en la misma unidad. No se guardó el grupo.'; END IF;

  IF p_pago IS NOT NULL AND COALESCE((p_pago->>'monto_clp')::integer,0)>0 THEN
    v_total_pago := (p_pago->>'monto_clp')::integer;
    SELECT COALESCE(sum((value->>'pago_asignado_clp')::integer),0) INTO v_total_asignado FROM jsonb_array_elements(p_reservas);
    IF v_total_asignado <> v_total_pago THEN RAISE EXCEPTION 'La distribución del pago suma % CLP, pero el pago total es % CLP',v_total_asignado,v_total_pago; END IF;
    v_metodo := (p_pago->>'metodo')::metodo_pago;
    v_moneda := COALESCE(NULLIF(p_pago->>'moneda',''),'CLP')::char(3);
    v_tipo_cambio := NULLIF(p_pago->>'tipo_cambio','')::numeric;
    v_monto_original := (p_pago->>'monto_original')::numeric;
    IF v_moneda='USD' AND (v_tipo_cambio IS NULL OR v_tipo_cambio<=0) THEN RAISE EXCEPTION 'Indica un tipo de cambio válido para pagos en USD'; END IF;
    IF v_monto_original<=0 THEN RAISE EXCEPTION 'El monto del pago debe ser mayor que cero'; END IF;
  END IF;

  INSERT INTO public.reserva_grupos(nombre,observaciones,creado_por)
  VALUES(COALESCE(NULLIF(p_nombre_grupo,''),'Reserva grupal'),NULLIF(p_observaciones_grupo,''),auth.uid()) RETURNING id INTO v_grupo;
  IF v_total_pago>0 THEN
    INSERT INTO public.pagos_compartidos(metodo,moneda,monto_original,tipo_cambio,monto_clp,id_transaccion,referencia,creado_por)
    VALUES(v_metodo::text,v_moneda,v_monto_original,v_tipo_cambio,v_total_pago,NULLIF(p_pago->>'id_transaccion',''),NULLIF(p_pago->>'referencia',''),auth.uid())
    RETURNING id INTO v_pago_id;
  END IF;

  FOR v_item IN SELECT value FROM jsonb_array_elements(p_reservas) LOOP
    v_idx:=v_idx+1; v_guest:=v_item->'huesped'; v_huesped:=NULLIF(v_item->>'huesped_id','')::uuid;
    IF COALESCE((v_item->>'huesped_compartido')::boolean,false) THEN
      IF v_shared_huesped IS NULL THEN
        v_shared_huesped:=v_huesped;
        IF v_shared_huesped IS NULL THEN
          INSERT INTO public.huespedes(nombre_completo,tipo_documento,numero_documento,telefono,correo,nacionalidad,ciudad_origen)
          VALUES(v_guest->>'nombre_completo',NULLIF(v_guest->>'tipo_documento',''),NULLIF(v_guest->>'numero_documento',''),NULLIF(v_guest->>'telefono',''),NULLIF(v_guest->>'correo',''),NULLIF(v_guest->>'nacionalidad',''),NULLIF(v_guest->>'ciudad_origen',''))
          RETURNING id INTO v_shared_huesped;
        END IF;
      END IF;
      v_huesped:=v_shared_huesped;
    ELSE
      IF v_huesped IS NULL THEN
        INSERT INTO public.huespedes(nombre_completo,tipo_documento,numero_documento,telefono,correo,nacionalidad,ciudad_origen)
        VALUES(v_guest->>'nombre_completo',NULLIF(v_guest->>'tipo_documento',''),NULLIF(v_guest->>'numero_documento',''),NULLIF(v_guest->>'telefono',''),NULLIF(v_guest->>'correo',''),NULLIF(v_guest->>'nacionalidad',''),NULLIF(v_guest->>'ciudad_origen',''))
        RETURNING id INTO v_huesped;
      ELSE
        UPDATE public.huespedes SET nombre_completo=v_guest->>'nombre_completo',tipo_documento=NULLIF(v_guest->>'tipo_documento',''),
          numero_documento=NULLIF(v_guest->>'numero_documento',''),telefono=NULLIF(v_guest->>'telefono',''),correo=NULLIF(v_guest->>'correo',''),
          nacionalidad=NULLIF(v_guest->>'nacionalidad',''),ciudad_origen=NULLIF(v_guest->>'ciudad_origen','') WHERE id=v_huesped;
        IF NOT FOUND THEN RAISE EXCEPTION 'No se encontró el huésped seleccionado en la reserva %',v_idx; END IF;
      END IF;
    END IF;
    v_reserva:=(v_item->'reserva')||jsonb_build_object('huesped_id',v_huesped);
    v_reserva_id:=public.crear_reserva_con_reacomodacion(v_reserva,COALESCE(v_item->'plan','[]'::jsonb),0,COALESCE((v_reserva->>'otro_total')::integer,0));
    UPDATE public.reservas SET observaciones=NULLIF(v_reserva->>'observaciones',''),
      huesped_nombre_copia=v_guest->>'nombre_completo',huesped_documento_copia=NULLIF(v_guest->>'numero_documento',''),
      huesped_telefono_copia=NULLIF(v_guest->>'telefono',''),
      hora_llegada_aprox=NULLIF(v_reserva->>'hora_llegada_aprox','')::time,
      hora_salida_aprox=NULLIF(v_reserva->>'hora_salida_aprox','')::time
      WHERE id=v_reserva_id;
    IF COALESCE((v_reserva->>'usa_estacionamiento')::boolean,false) THEN
      SELECT array_agg(x::date) INTO v_fechas FROM jsonb_array_elements_text(COALESCE(v_item->'parking_fechas','[]'::jsonb)) x;
      IF COALESCE(cardinality(v_fechas),0)<1 THEN RAISE EXCEPTION 'Selecciona las fechas de estacionamiento de la reserva %',v_idx; END IF;
      v_perm_sobrecupo:=COALESCE((v_item->>'permitir_sobrecupo')::boolean,false);
      PERFORM * FROM public.guardar_fechas_estacionamiento(v_fechas,v_reserva_id,v_perm_sobrecupo);
    END IF;
    INSERT INTO public.reserva_grupo_miembros(grupo_id,reserva_id,orden) VALUES(v_grupo,v_reserva_id,v_idx);
    v_ids:=v_ids||jsonb_build_array(jsonb_build_object('reserva_id',v_reserva_id,'orden',v_idx));
    v_alloc:=COALESCE((v_item->>'pago_asignado_clp')::integer,0);
    IF v_pago_id IS NOT NULL AND v_alloc>0 THEN
      INSERT INTO public.pagos(reserva_id,metodo,moneda,monto_original,tipo_cambio,monto_clp,referencia,anticipado,motivo,id_transaccion,creado_por)
      VALUES(v_reserva_id,v_metodo,v_moneda,CASE WHEN v_moneda='USD' THEN round(v_alloc/v_tipo_cambio,2) ELSE v_alloc END,
        v_tipo_cambio,v_alloc,NULLIF(p_pago->>'referencia',''),false,'estadia',NULLIF(p_pago->>'id_transaccion',''),auth.uid()) RETURNING id INTO v_pago_fila;
      INSERT INTO public.pagos_compartidos_distribucion(pago_compartido_id,reserva_id,pago_id,motivo,monto_clp)
      VALUES(v_pago_id,v_reserva_id,v_pago_fila,'estadia',v_alloc);
    END IF;
  END LOOP;
  RETURN jsonb_build_object('grupo_id',v_grupo,'reservas',v_ids,'pago_compartido_id',v_pago_id);
END;
$function$;

CREATE OR REPLACE FUNCTION public.buscar_reacomodacion(p_unidad_id uuid, p_entrada date, p_salida date, p_excluir_reserva uuid DEFAULT NULL::uuid)
 RETURNS TABLE(unidad_id uuid, unidad_codigo text, edificio_id uuid, categoria_id uuid, categoria text, ranking integer, upgrade boolean, reservas_bloqueantes bigint)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  with objetivo as (
    select u.edificio_id, u.tipo_unidad_id, coalesce(cr.ranking,0) ranking
    from unidades u
    left join categoria_ranking_edificio cr
      on cr.edificio_id=u.edificio_id
     and cr.tipo_unidad_id=u.tipo_unidad_id
    where u.id=p_unidad_id AND public.pms_rol() IN ('recepcion','administracion','gerencia','sysadmin') AND public.puede_ver_edificio(u.edificio_id)
  )
  select
    u.id,
    u.codigo::text,
    u.edificio_id,
    u.tipo_unidad_id,
    tu.nombre::text,
    coalesce(cr.ranking,0),
    coalesce(cr.ranking,0) > o.ranking,
    count(r.id)
  from unidades u
  join tipos_unidad tu on tu.id=u.tipo_unidad_id
  cross join objetivo o
  left join categoria_ranking_edificio cr
    on cr.edificio_id=u.edificio_id
   and cr.tipo_unidad_id=u.tipo_unidad_id
  left join reservas r
    on r.unidad_id=u.id
   and r.id is distinct from p_excluir_reserva
   and r.estado in ('tentativa','confirmada','en_casa','bloqueado')
   and r.fecha_entrada < p_salida
   and r.fecha_salida > p_entrada
  where u.activo
    and u.edificio_id=o.edificio_id
  group by u.id,u.codigo,u.edificio_id,u.tipo_unidad_id,tu.nombre,cr.ranking,o.ranking
  having count(r.id)=0
  order by
    (coalesce(cr.ranking,0)=o.ranking) desc,
    abs(coalesce(cr.ranking,0)-o.ranking),
    coalesce(cr.ranking,0),
    u.codigo;
$function$;

CREATE OR REPLACE FUNCTION public.buscar_reacomodacion(p_edificio_id uuid, p_tipo_unidad_id uuid, p_entrada date, p_salida date, p_excluir_reserva uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE v_target uuid;v_blocker reservas%rowtype;v_plan jsonb;
BEGIN
 IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') OR NOT public.puede_ver_edificio(p_edificio_id) THEN RAISE EXCEPTION 'Sesión o rol no autorizado'; END IF;
 IF p_salida<=p_entrada THEN RETURN '[]'::jsonb;END IF;
 SELECT u.id INTO v_target FROM unidades u WHERE u.activo AND u.edificio_id=p_edificio_id AND u.tipo_unidad_id=p_tipo_unidad_id
 AND NOT EXISTS(SELECT 1 FROM reservas r WHERE r.unidad_id=u.id AND r.id IS DISTINCT FROM p_excluir_reserva AND r.fecha_entrada<p_salida AND r.fecha_salida>p_entrada AND r.estado NOT IN ('cancelada','no_show')) ORDER BY u.orden,u.codigo LIMIT 1;
 IF v_target IS NOT NULL THEN RETURN jsonb_build_object('unidad_id',v_target,'plan','[]'::jsonb);END IF;
 FOR v_target IN SELECT u.id FROM unidades u WHERE u.activo AND u.edificio_id=p_edificio_id AND u.tipo_unidad_id=p_tipo_unidad_id
 AND (SELECT count(*) FROM reservas r WHERE r.unidad_id=u.id AND r.id IS DISTINCT FROM p_excluir_reserva AND r.fecha_entrada<p_salida AND r.fecha_salida>p_entrada AND r.estado NOT IN ('cancelada','no_show'))=1 ORDER BY u.orden,u.codigo LOOP
  SELECT r.* INTO v_blocker FROM reservas r WHERE r.unidad_id=v_target AND r.id IS DISTINCT FROM p_excluir_reserva AND r.fecha_entrada<p_salida AND r.fecha_salida>p_entrada AND r.estado NOT IN ('cancelada','no_show') LIMIT 1;
  IF v_blocker.estado='en_casa' OR v_blocker.estado='bloqueado' OR COALESCE(v_blocker.no_mover_unidad,false) THEN CONTINUE;END IF;
  WITH RECURSIVE chain AS(
   SELECT v_blocker.id rid,v_blocker.unidad_id from_uid,c.id to_uid,1 depth,ARRAY[v_blocker.id]::uuid[] seen_r,ARRAY[v_target]::uuid[] seen_u
   FROM unidades c JOIN unidades src ON src.id=v_blocker.unidad_id LEFT JOIN categoria_ranking_edificio rs ON rs.edificio_id=src.edificio_id AND rs.tipo_unidad_id=src.tipo_unidad_id LEFT JOIN categoria_ranking_edificio rc ON rc.edificio_id=c.edificio_id AND rc.tipo_unidad_id=c.tipo_unidad_id
   WHERE c.activo AND c.edificio_id=src.edificio_id AND c.id<>v_blocker.unidad_id AND c.id<>v_target AND (c.tipo_unidad_id=src.tipo_unidad_id OR COALESCE(rc.ranking,0)>COALESCE(rs.ranking,0))
   UNION ALL
   SELECT b.id,b.unidad_id,c.id,ch.depth+1,ch.seen_r||b.id,ch.seen_u||c.id
   FROM chain ch JOIN reservas cur ON cur.id=ch.rid JOIN unidades src ON src.id=cur.unidad_id JOIN unidades c ON c.activo AND c.edificio_id=src.edificio_id AND c.id<>cur.unidad_id
   LEFT JOIN categoria_ranking_edificio rs ON rs.edificio_id=src.edificio_id AND rs.tipo_unidad_id=src.tipo_unidad_id LEFT JOIN categoria_ranking_edificio rc ON rc.edificio_id=c.edificio_id AND rc.tipo_unidad_id=c.tipo_unidad_id
   LEFT JOIN LATERAL(SELECT r.id,r.estado,r.fecha_entrada,r.fecha_salida,r.unidad_id,r.no_mover_unidad FROM reservas r WHERE r.unidad_id=c.id AND r.id IS DISTINCT FROM p_excluir_reserva AND r.fecha_entrada<cur.fecha_salida AND r.fecha_salida>cur.fecha_entrada AND r.estado NOT IN ('cancelada','no_show') AND r.id<>ALL(ch.seen_r) LIMIT 1)b ON true
   WHERE ch.depth<6 AND (c.tipo_unidad_id=src.tipo_unidad_id OR COALESCE(rc.ranking,0)>COALESCE(rs.ranking,0)) AND c.id<>ALL(ch.seen_u) AND (b.id IS NULL OR (b.estado<>'en_casa' AND b.estado<>'bloqueado' AND NOT COALESCE(b.no_mover_unidad,false)))
  ),terminals AS(
   SELECT ch.* FROM chain ch JOIN reservas cur ON cur.id=ch.rid WHERE NOT EXISTS(SELECT 1 FROM reservas b WHERE b.unidad_id=ch.to_uid AND b.id IS DISTINCT FROM p_excluir_reserva AND b.fecha_entrada<cur.fecha_salida AND b.fecha_salida>cur.fecha_entrada AND b.estado NOT IN ('cancelada','no_show'))
  )
  SELECT jsonb_agg(jsonb_build_object('reserva_id',rid,'unidad_origen',from_uid,'unidad_destino',to_uid,'profundidad',depth) ORDER BY depth DESC) INTO v_plan FROM terminals;
  IF v_plan IS NOT NULL THEN RETURN jsonb_build_object('unidad_id',v_target,'plan',v_plan);END IF;
 END LOOP;RETURN '[]'::jsonb;
END $function$;

CREATE OR REPLACE FUNCTION public.ejecutar_extension_estadia(p_reserva_id uuid, p_nueva_entrada date, p_nueva_salida date, p_plan jsonb DEFAULT '[]'::jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  r reservas%rowtype;
  x jsonb;
  v_ids uuid[];
  v_count integer;
  c record;
BEGIN
  IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RAISE EXCEPTION 'Sesión o rol no autorizado'; END IF;

  SELECT *
  INTO r
  FROM public.reservas rr
  WHERE rr.id = p_reserva_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Reserva no encontrada';
  END IF;

  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=r.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF r.estado IN ('cancelada','no_show','bloqueado','check_out') THEN
    RAISE EXCEPTION 'Esta reserva no puede extenderse en su estado actual';
  END IF;

  IF p_nueva_entrada > r.fecha_entrada
     OR p_nueva_salida < r.fecha_salida
  THEN
    RAISE EXCEPTION 'Las nuevas fechas no pueden reducir la estadía actual';
  END IF;

  IF p_nueva_salida <= p_nueva_entrada THEN
    RAISE EXCEPTION 'La salida debe ser posterior a la entrada';
  END IF;

  IF p_nueva_entrada < r.fecha_entrada
     AND r.estado = 'en_casa'
  THEN
    RAISE EXCEPTION 'No se puede extender hacia atrás una estadía que ya está en casa';
  END IF;

  IF p_plan IS NULL THEN
    p_plan := '[]'::jsonb;
  END IF;

  IF EXISTS (SELECT 1 FROM jsonb_array_elements(p_plan) pl(value) JOIN public.reservas rr ON rr.id=(pl.value->>'reserva_id')::uuid JOIN public.unidades uo ON uo.id=rr.unidad_id LEFT JOIN public.unidades ud ON ud.id=(pl.value->>'unidad_destino')::uuid WHERE NOT public.puede_ver_edificio(uo.edificio_id) OR ud.id IS NULL OR NOT public.puede_ver_edificio(ud.edificio_id)) THEN RAISE EXCEPTION 'No tienes acceso a una reacomodación del plan'; END IF;
  FOR c IN
    SELECT conname
    FROM pg_constraint
    WHERE conrelid = 'public.reservas'::regclass
      AND contype = 'x'
      AND condeferrable
  LOOP
    EXECUTE format(
      'SET CONSTRAINTS %I DEFERRED',
      c.conname
    );
  END LOOP;

  SELECT COALESCE(
    array_agg((value->>'reserva_id')::uuid),
    ARRAY[]::uuid[]
  )
  INTO v_ids
  FROM jsonb_array_elements(p_plan);

  SELECT count(*)
  INTO v_count
  FROM (
    SELECT DISTINCT value->>'reserva_id' AS reserva_id
    FROM jsonb_array_elements(p_plan)
  ) q;

  IF v_count <> jsonb_array_length(p_plan) THEN
    RAISE EXCEPTION
      'El plan de reacomodación contiene reservas duplicadas';
  END IF;

  IF p_reserva_id = ANY(v_ids) THEN
    RAISE EXCEPTION
      'El plan de reacomodación no puede contener la reserva que se está extendiendo';
  END IF;

  PERFORM 1
  FROM public.reservas rr
  WHERE rr.id = ANY(v_ids)
  FOR UPDATE;

  IF (
    SELECT count(*)
    FROM public.reservas rr
    WHERE rr.id = ANY(v_ids)
  ) <> v_count
  THEN
    RAISE EXCEPTION 'Reserva del plan no encontrada';
  END IF;

  FOR x IN
    SELECT value
    FROM jsonb_array_elements(p_plan)
  LOOP

    SELECT *
    INTO r
    FROM public.reservas rr
    WHERE rr.id = (x->>'reserva_id')::uuid;

    IF r.estado IN ('cancelada','no_show') THEN
      RAISE EXCEPTION 'La reserva % ya no está activa', r.uid_reserva;
    END IF;

    IF r.estado IN ('en_casa','bloqueado')
       OR COALESCE(r.no_mover_unidad,false)
    THEN
      RAISE EXCEPTION
        'La reserva % no puede ser reacomodada', r.uid_reserva;
    END IF;

    IF r.unidad_id <> (x->>'unidad_origen')::uuid THEN
      RAISE EXCEPTION
        'La cadena ya no es válida: la reserva % cambió de unidad',
        r.uid_reserva;
    END IF;

    IF NOT EXISTS (
      SELECT 1
      FROM public.unidades u
      WHERE u.id = (x->>'unidad_destino')::uuid
        AND u.activo
        AND u.id <> (
          SELECT unidad_id
          FROM public.reservas
          WHERE id = p_reserva_id
        )
    ) THEN
      RAISE EXCEPTION
        'Una reserva del plan intenta ocupar la unidad de la estadía extendida';
    END IF;

    IF EXISTS (
      SELECT 1
      FROM public.reservas q
      WHERE q.unidad_id = (x->>'unidad_destino')::uuid
        AND q.id <> r.id
        AND q.id <> p_reserva_id
        AND NOT (q.id = ANY(v_ids))
        AND q.fecha_entrada < r.fecha_salida
        AND q.fecha_salida > r.fecha_entrada
        AND q.estado NOT IN ('cancelada','no_show')
    ) THEN
      RAISE EXCEPTION
        'La reacomodación ya no es válida: una unidad destino quedó ocupada';
    END IF;

  END LOOP;

  UPDATE public.reservas rr
  SET
    unidad_id = p.unidad_destino,
    actualizado_en = now()
  FROM (
    SELECT
      (value->>'reserva_id')::uuid AS reserva_id,
      (value->>'unidad_destino')::uuid AS unidad_destino
    FROM jsonb_array_elements(p_plan)
  ) p
  WHERE rr.id = p.reserva_id;

  -- IMPORTANTE:
  -- "noches" se recalcula mediante DEFAULT.
  -- No se le asigna manualmente un número.
  UPDATE public.reservas
  SET
    fecha_entrada = p_nueva_entrada,
    fecha_salida = p_nueva_salida,
    noches = DEFAULT,
    actualizado_en = now()
  WHERE id = p_reserva_id;

  IF EXISTS (
    SELECT 1
    FROM (
      SELECT
        (value->>'reserva_id')::uuid AS reserva_id,
        (value->>'unidad_destino')::uuid AS unidad_destino
      FROM jsonb_array_elements(p_plan)
    ) p
    JOIN public.reservas rr
      ON rr.id = p.reserva_id
    WHERE rr.unidad_id <> p.unidad_destino
  ) THEN
    RAISE EXCEPTION 'No se pudo completar la reacomodación de la extensión';
  END IF;

  SELECT *
  INTO r
  FROM public.reservas rr
  WHERE rr.id = p_reserva_id;

  IF r.fecha_entrada <> p_nueva_entrada
     OR r.fecha_salida <> p_nueva_salida
  THEN
    RAISE EXCEPTION 'No se pudo actualizar la nueva estadía';
  END IF;

END;
$function$;

CREATE OR REPLACE FUNCTION public.hacer_check_in(p_reserva_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_estado estado_reserva;
  v_id uuid;
BEGIN
  IF auth.uid() IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión no válida';
  END IF;

  SELECT estado
    INTO v_estado
    FROM public.reservas
   WHERE id = p_reserva_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Reserva no encontrada';
  END IF;

  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.reservas r JOIN public.unidades u ON u.id=r.unidad_id WHERE r.id=p_reserva_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF v_estado <> 'confirmada'::estado_reserva THEN
    RAISE EXCEPTION 'La reserva no esta confirmada';
  END IF;

  UPDATE public.reservas
     SET estado = 'en_casa'::estado_reserva,
         entrada_real = COALESCE(entrada_real, now())
   WHERE id = p_reserva_id
     AND estado = 'confirmada'::estado_reserva
   RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    RAISE EXCEPTION 'La reserva cambió de estado antes de completar el check-in';
  END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.cancelar_reserva_pms_v1101(p_reserva_id uuid, p_motivo text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_user uuid := auth.uid();
  v_reserva public.reservas%rowtype;
BEGIN
  IF v_user IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión no válida o sin perfil de personal activo';
  END IF;
  SELECT r.* INTO v_reserva
    FROM public.reservas r WHERE r.id=p_reserva_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Reserva no encontrada'; END IF;
  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_reserva.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF v_reserva.estado='cancelada' THEN RETURN 0; END IF;
  IF v_reserva.estado NOT IN ('tentativa','confirmada') THEN
    RAISE EXCEPTION 'Solo se pueden cancelar reservas en estado tentativa o confirmada. Estado actual: %',v_reserva.estado;
  END IF;
  IF NULLIF(trim(COALESCE(p_motivo,'')),'') IS NULL THEN
    RAISE EXCEPTION 'Debes indicar el motivo de cancelación';
  END IF;

  UPDATE public.reservas
     SET estado='cancelada',
         cancelada_en=now(),
         cancelada_por=v_user,
         motivo_cancelacion=trim(p_motivo)
   WHERE id=p_reserva_id AND estado IN ('tentativa','confirmada');

  IF NOT EXISTS (SELECT 1 FROM public.reservas r WHERE r.id=p_reserva_id AND r.estado='cancelada') THEN
    RAISE EXCEPTION 'La reserva no quedó cancelada';
  END IF;
  RETURN 0;
END;
$function$;

CREATE OR REPLACE FUNCTION public.ejecutar_reacomodacion_cambio_unidad(p_reserva_id uuid, p_unidad_destino uuid, p_entrada date, p_salida date, p_plan jsonb DEFAULT '[]'::jsonb, p_tarifa integer DEFAULT NULL::integer)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_user uuid := auth.uid();
  v_rol text := lower(trim(COALESCE(public.rol_actual()::text,'')));
  v_principal public.reservas%rowtype;
  v_reserva public.reservas%rowtype;
  v_obj jsonb;
  v_ids uuid[] := ARRAY[]::uuid[];
  v_plan_count integer := 0;
  v_encontradas integer := 0;
  v_target_edificio uuid;
  v_cupos integer;
  v_fechas_parking date[] := ARRAY[]::date[];
  v_inconsistente uuid;
  v_fecha_llena date;
  v_constraint record;
BEGIN
  IF v_user IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión no válida o sin perfil de personal activo';
  END IF;

  SELECT r.* INTO v_principal
    FROM public.reservas r WHERE r.id=p_reserva_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Reserva principal no encontrada'; END IF;
  IF v_principal.estado IN ('en_casa','bloqueado','cancelada','no_show','check_out') THEN
    RAISE EXCEPTION 'Esta reserva no puede cambiar de unidad en su estado actual';
  END IF;
  IF v_principal.fecha_entrada IS DISTINCT FROM p_entrada
     OR v_principal.fecha_salida IS DISTINCT FROM p_salida THEN
    RAISE EXCEPTION 'La cadena ya no es válida: las fechas de la reserva principal cambiaron';
  END IF;
  IF p_unidad_destino IS NULL THEN RAISE EXCEPTION 'Debes indicar la unidad de destino'; END IF;

  IF NOT COALESCE(public.tiene_permiso_edicion(v_user,'building_category_unit'),false)
     AND v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin') THEN
    RAISE EXCEPTION 'No tienes permiso para cambiar la unidad de esta reserva';
  END IF;

  SELECT u.edificio_id,e.cupos_estacionamiento INTO v_target_edificio,v_cupos
    FROM public.unidades u
    JOIN public.edificios e ON e.id=u.edificio_id
   WHERE u.id=p_unidad_destino AND u.activo
   FOR UPDATE OF u,e;
  IF NOT FOUND THEN RAISE EXCEPTION 'La unidad de destino no existe o está inactiva'; END IF;

  IF v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin')
     AND (
       NOT EXISTS (SELECT 1 FROM public.perfiles_edificios pe
                    WHERE pe.perfil_id=v_user
                      AND pe.edificio_id=(SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_principal.unidad_id))
       OR NOT EXISTS (SELECT 1 FROM public.perfiles_edificios pe
                       WHERE pe.perfil_id=v_user AND pe.edificio_id=v_target_edificio)
     ) THEN
    RAISE EXCEPTION 'No tienes permiso para mover reservas entre estos edificios';
  END IF;

  IF p_plan IS NULL THEN p_plan:='[]'::jsonb; END IF;
  IF jsonb_typeof(p_plan)<>'array' THEN RAISE EXCEPTION 'El plan de reacomodación tiene un formato inválido'; END IF;

  SELECT COALESCE(array_agg((value->>'reserva_id')::uuid),ARRAY[]::uuid[])
    INTO v_ids FROM jsonb_array_elements(p_plan);
  SELECT count(DISTINCT value->>'reserva_id')::integer
    INTO v_plan_count FROM jsonb_array_elements(p_plan);
  IF v_plan_count<>jsonb_array_length(p_plan) THEN
    RAISE EXCEPTION 'La cadena de reacomodación contiene reservas duplicadas';
  END IF;
  IF p_reserva_id=ANY(v_ids) THEN
    RAISE EXCEPTION 'La cadena de reacomodación no puede contener la reserva principal';
  END IF;

  PERFORM r.id FROM public.reservas r
   WHERE r.id=ANY(v_ids) ORDER BY r.id FOR UPDATE;
  SELECT count(*)::integer INTO v_encontradas
    FROM public.reservas r WHERE r.id=ANY(v_ids);
  IF v_encontradas<>v_plan_count THEN RAISE EXCEPTION 'No se encontraron todas las reservas del plan'; END IF;

  FOR v_constraint IN
    SELECT conname FROM pg_constraint
     WHERE conrelid='public.reservas'::regclass AND contype='x' AND condeferrable
  LOOP
    EXECUTE format('SET CONSTRAINTS %I DEFERRED',v_constraint.conname);
  END LOOP;

  -- Validar todos los integrantes y todas las unidades antes de escribir.
  FOR v_obj IN SELECT value FROM jsonb_array_elements(p_plan)
  LOOP
    SELECT r.* INTO v_reserva FROM public.reservas r
     WHERE r.id=(v_obj->>'reserva_id')::uuid;

    IF v_reserva.unidad_id IS DISTINCT FROM (v_obj->>'unidad_origen')::uuid THEN
      RAISE EXCEPTION 'La cadena ya no es válida: la reserva % cambió de unidad',v_reserva.uid_reserva;
    END IF;
    IF v_reserva.estado IN ('en_casa','bloqueado','cancelada','no_show','check_out')
       OR COALESCE(v_reserva.no_mover_unidad,false) THEN
      RAISE EXCEPTION 'La reserva % no puede reacomodarse automáticamente',v_reserva.uid_reserva;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.unidades u
                    WHERE u.id=(v_obj->>'unidad_destino')::uuid AND u.activo) THEN
      RAISE EXCEPTION 'La unidad destino de la reserva % no existe o está inactiva',v_reserva.uid_reserva;
    END IF;
    IF v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin')
       AND (
         NOT EXISTS (SELECT 1 FROM public.perfiles_edificios pe
                      WHERE pe.perfil_id=v_user
                        AND pe.edificio_id=(SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_reserva.unidad_id))
         OR NOT EXISTS (SELECT 1 FROM public.perfiles_edificios pe
                         WHERE pe.perfil_id=v_user
                           AND pe.edificio_id=(SELECT u.edificio_id FROM public.unidades u WHERE u.id=(v_obj->>'unidad_destino')::uuid))
       ) THEN
      RAISE EXCEPTION 'No tienes permiso para una de las reservas o edificios de la cadena';
    END IF;

    -- Una reserva fuera de la cadena sí bloquea su destino; las reservas
    -- del plan y la principal se excluyen para permitir ciclos/intercambios.
    IF EXISTS (
      SELECT 1 FROM public.reservas q
       WHERE q.unidad_id=(v_obj->>'unidad_destino')::uuid
         AND q.id<>p_reserva_id
         AND NOT (q.id=ANY(v_ids))
         AND q.fecha_entrada<v_reserva.fecha_salida
         AND q.fecha_salida>v_reserva.fecha_entrada
         AND q.estado IN ('tentativa','confirmada','en_casa','bloqueado')
    ) THEN
      RAISE EXCEPTION 'La reacomodación ya no es válida: una reserva fuera del plan ocupa el destino';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
      FROM jsonb_array_elements(p_plan) a(value)
      JOIN jsonb_array_elements(p_plan) b(value)
        ON (a.value->>'reserva_id')::uuid < (b.value->>'reserva_id')::uuid
      JOIN public.reservas ra ON ra.id=(a.value->>'reserva_id')::uuid
      JOIN public.reservas rb ON rb.id=(b.value->>'reserva_id')::uuid
     WHERE (a.value->>'unidad_destino')::uuid=(b.value->>'unidad_destino')::uuid
       AND ra.fecha_entrada<rb.fecha_salida AND ra.fecha_salida>rb.fecha_entrada
  ) THEN
    RAISE EXCEPTION 'La cadena contiene dos reservas superpuestas para la misma unidad';
  END IF;

  -- No usar mover_reserva ni editar_reserva_completa; sus verificaciones
  -- históricas no excluían el resto del plan y generaban el falso destino ocupado.
  IF cardinality(v_ids)>0 THEN
    UPDATE public.reservas r
       SET unidad_id=(p.value->>'unidad_destino')::uuid,
           actualizado_en=now()
      FROM jsonb_array_elements(p_plan) p(value)
     WHERE r.id=(p.value->>'reserva_id')::uuid;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.reservas q
     WHERE q.unidad_id=p_unidad_destino
       AND q.id<>p_reserva_id AND NOT (q.id=ANY(v_ids))
       AND q.fecha_entrada<p_salida AND q.fecha_salida>p_entrada
       AND q.estado IN ('tentativa','confirmada','en_casa','bloqueado')
  ) THEN
    RAISE EXCEPTION 'La unidad de destino sigue ocupada fuera del plan de reacomodación';
  END IF;

  -- Validar parking según fechas elegidas manualmente en la reserva principal.
  SELECT COALESCE(array_agg(f.fecha ORDER BY f.fecha),ARRAY[]::date[])
    INTO v_fechas_parking
    FROM public.estacionamiento_reserva_fechas f WHERE f.reserva_id=p_reserva_id;
  IF COALESCE(v_principal.usa_estacionamiento,false) THEN
    IF cardinality(v_fechas_parking)<>COALESCE(v_principal.noches_estacionamiento,0) THEN
      RAISE EXCEPTION 'Las fechas manuales de estacionamiento de la reserva principal están incompletas';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(v_fechas_parking) f(fecha)
                WHERE f.fecha<v_principal.fecha_entrada OR f.fecha>=v_principal.fecha_salida) THEN
      RAISE EXCEPTION 'La reserva principal tiene fechas de estacionamiento fuera de su estadía';
    END IF;
    IF cardinality(v_fechas_parking)>0 AND COALESCE(v_cupos,0)<=0 THEN
      RAISE EXCEPTION 'El edificio destino no tiene cupos de estacionamiento definidos';
    END IF;
    IF cardinality(v_fechas_parking)>0 THEN
      SELECT r.id INTO v_inconsistente
        FROM public.reservas r
        JOIN public.unidades u ON u.id=r.unidad_id
       WHERE r.id<>p_reserva_id AND r.usa_estacionamiento
         AND r.estado IN ('tentativa','confirmada','en_casa')
         AND u.edificio_id=v_target_edificio
         AND EXISTS (SELECT 1 FROM unnest(v_fechas_parking) f(fecha)
                      WHERE f.fecha>=r.fecha_entrada AND f.fecha<r.fecha_salida)
         AND (
           COALESCE(r.noches_estacionamiento,0) <>
             (SELECT count(*)::integer FROM public.estacionamiento_reserva_fechas f WHERE f.reserva_id=r.id)
           OR EXISTS (SELECT 1 FROM public.estacionamiento_reserva_fechas f
                       WHERE f.reserva_id=r.id AND (f.fecha<r.fecha_entrada OR f.fecha>=r.fecha_salida))
         )
       LIMIT 1;
      IF v_inconsistente IS NOT NULL THEN
        RAISE EXCEPTION 'La reserva % tiene fechas de estacionamiento incompletas; no se puede validar el destino',v_inconsistente;
      END IF;
      SELECT f.fecha INTO v_fecha_llena
        FROM unnest(v_fechas_parking) f(fecha)
       WHERE (SELECT count(DISTINCT r.id)::integer
                FROM public.estacionamiento_reserva_fechas pf
                JOIN public.reservas r ON r.id=pf.reserva_id
                JOIN public.unidades u ON u.id=r.unidad_id
               WHERE pf.fecha=f.fecha AND r.id<>p_reserva_id
                 AND r.usa_estacionamiento AND r.estado IN ('tentativa','confirmada','en_casa')
                 AND u.edificio_id=v_target_edificio
                 AND f.fecha>=r.fecha_entrada AND f.fecha<r.fecha_salida)>=v_cupos
       ORDER BY f.fecha LIMIT 1;
      IF v_fecha_llena IS NOT NULL THEN
        RAISE EXCEPTION 'No hay cupo de estacionamiento para la noche % en el edificio destino',v_fecha_llena;
      END IF;
    END IF;
  END IF;

  -- La columna GENERATED noches no se escribe ni se asigna a DEFAULT.
  UPDATE public.reservas r
     SET unidad_id=p_unidad_destino,
         tarifa_noche=COALESCE(p_tarifa,r.tarifa_noche),
         cupo_estacionamiento=NULL
   WHERE r.id=p_reserva_id;

  IF EXISTS (
    SELECT 1
      FROM public.reservas a
      JOIN public.reservas b
        ON a.unidad_id=b.unidad_id AND a.id<b.id
       AND a.fecha_entrada<b.fecha_salida AND a.fecha_salida>b.fecha_entrada
     WHERE a.estado IN ('tentativa','confirmada','en_casa','bloqueado')
       AND b.estado IN ('tentativa','confirmada','en_casa','bloqueado')
       AND (a.id=p_reserva_id OR b.id=p_reserva_id OR a.id=ANY(v_ids) OR b.id=ANY(v_ids))
  ) THEN
    RAISE EXCEPTION 'La reacomodación produciría una superposición real de reservas';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM public.reservas r
                  WHERE r.id=p_reserva_id AND r.unidad_id=p_unidad_destino
                    AND r.fecha_entrada=p_entrada AND r.fecha_salida=p_salida) THEN
    RAISE EXCEPTION 'No se pudo completar el cambio de unidad';
  END IF;

  IF cardinality(v_ids)>0 AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_plan) p(value)
    LEFT JOIN public.reservas r ON r.id=(p.value->>'reserva_id')::uuid
    WHERE r.id IS NULL OR r.unidad_id IS DISTINCT FROM (p.value->>'unidad_destino')::uuid
  ) THEN
    RAISE EXCEPTION 'La reacomodación quedó incompleta: una reserva no llegó a su destino';
  END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.mover_reserva_arrastrada(p_reserva_id uuid, p_unidad_id uuid, p_entrada date, p_salida date, p_tarifa integer)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_user uuid := auth.uid();
  v_rol text := lower(trim(COALESCE(public.rol_actual()::text, '')));
  v_reserva public.reservas%rowtype;
  v_edificio_id uuid;
  v_cupos integer;
  v_shift integer;
  v_fechas_antiguas date[] := ARRAY[]::date[];
  v_fechas_nuevas date[] := ARRAY[]::date[];
  v_count integer := 0;
  v_inconsistente uuid;
  v_fecha_llena date;
BEGIN
  IF v_user IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión no válida o sin perfil de personal activo';
  END IF;

  SELECT r.* INTO v_reserva
    FROM public.reservas r
   WHERE r.id = p_reserva_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Reserva no encontrada'; END IF;

  IF v_reserva.estado IN ('en_casa','bloqueado','cancelada','no_show','check_out') THEN
    RAISE EXCEPTION 'Esta reserva no puede moverse mediante arrastre en su estado actual';
  END IF;
  IF p_entrada IS NULL OR p_salida IS NULL OR p_salida <= p_entrada THEN
    RAISE EXCEPTION 'La salida debe ser posterior a la entrada';
  END IF;
  IF p_unidad_id IS NULL THEN RAISE EXCEPTION 'Debes indicar una unidad de destino'; END IF;

  IF (p_entrada IS DISTINCT FROM v_reserva.fecha_entrada
      OR p_salida IS DISTINCT FROM v_reserva.fecha_salida)
     AND NOT COALESCE(public.tiene_permiso_edicion(v_user, 'dates'), false)
     AND v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin') THEN
    RAISE EXCEPTION 'No tienes permiso para modificar las fechas de la reserva';
  END IF;
  IF p_unidad_id IS DISTINCT FROM v_reserva.unidad_id
     AND NOT COALESCE(public.tiene_permiso_edicion(v_user, 'building_category_unit'), false)
     AND v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin') THEN
    RAISE EXCEPTION 'No tienes permiso para cambiar la unidad de esta reserva';
  END IF;

  SELECT u.edificio_id, e.cupos_estacionamiento
    INTO v_edificio_id, v_cupos
    FROM public.unidades u
    JOIN public.edificios e ON e.id = u.edificio_id
   WHERE u.id = p_unidad_id AND u.activo
   FOR UPDATE OF u, e;
  IF NOT FOUND THEN RAISE EXCEPTION 'La unidad de destino no existe o está inactiva'; END IF;

  IF v_rol NOT IN ('administracion','gerencia','sysadmin','system_admin','systemadmin')
     AND (
       NOT EXISTS (
         SELECT 1 FROM public.perfiles_edificios pe
          WHERE pe.perfil_id = v_user
            AND pe.edificio_id = (SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_reserva.unidad_id)
       )
       OR NOT EXISTS (
         SELECT 1 FROM public.perfiles_edificios pe
          WHERE pe.perfil_id = v_user AND pe.edificio_id = v_edificio_id
       )
     ) THEN
    RAISE EXCEPTION 'No tienes permiso para mover reservas entre estos edificios';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.reservas q
     WHERE q.unidad_id = p_unidad_id AND q.id <> p_reserva_id
       AND q.fecha_entrada < p_salida AND q.fecha_salida > p_entrada
       AND q.estado IN ('tentativa','confirmada','en_casa','bloqueado')
  ) THEN
    RAISE EXCEPTION 'La unidad de destino está ocupada durante una parte de esas fechas';
  END IF;

  v_shift := p_entrada - v_reserva.fecha_entrada;
  SELECT COALESCE(array_agg(f.fecha ORDER BY f.fecha), ARRAY[]::date[])
    INTO v_fechas_antiguas
    FROM public.estacionamiento_reserva_fechas f
   WHERE f.reserva_id = p_reserva_id;

  IF COALESCE(v_reserva.usa_estacionamiento, false) THEN
    IF cardinality(v_fechas_antiguas) <> COALESCE(v_reserva.noches_estacionamiento,0) THEN
      RAISE EXCEPTION 'Las fechas manuales de estacionamiento no coinciden con el contador (% frente a %)',
        cardinality(v_fechas_antiguas), COALESCE(v_reserva.noches_estacionamiento,0);
    END IF;
    IF EXISTS (
      SELECT 1 FROM unnest(v_fechas_antiguas) f(fecha)
       WHERE f.fecha < v_reserva.fecha_entrada OR f.fecha >= v_reserva.fecha_salida
    ) THEN
      RAISE EXCEPTION 'Hay fechas de estacionamiento fuera de la estadía actual';
    END IF;
    SELECT COALESCE(array_agg(x.fecha + v_shift ORDER BY x.fecha + v_shift), ARRAY[]::date[])
      INTO v_fechas_nuevas
      FROM unnest(v_fechas_antiguas) x(fecha)
     WHERE x.fecha + v_shift >= p_entrada AND x.fecha + v_shift < p_salida;
  ELSE
    v_fechas_nuevas := ARRAY[]::date[];
  END IF;

  IF cardinality(v_fechas_nuevas) > 0 THEN
    IF COALESCE(v_cupos,0) <= 0 THEN
      RAISE EXCEPTION 'El edificio de destino no tiene cupos de estacionamiento definidos';
    END IF;

    SELECT r.id INTO v_inconsistente
      FROM public.reservas r
      JOIN public.unidades u ON u.id=r.unidad_id
     WHERE r.id<>p_reserva_id AND r.usa_estacionamiento
       AND r.estado IN ('tentativa','confirmada','en_casa')
       AND u.edificio_id=v_edificio_id
       AND EXISTS (SELECT 1 FROM unnest(v_fechas_nuevas) x(fecha)
                    WHERE x.fecha>=r.fecha_entrada AND x.fecha<r.fecha_salida)
       AND (
         COALESCE(r.noches_estacionamiento,0) <>
          (SELECT count(*)::integer FROM public.estacionamiento_reserva_fechas f WHERE f.reserva_id=r.id)
         OR EXISTS (SELECT 1 FROM public.estacionamiento_reserva_fechas f
          WHERE f.reserva_id=r.id AND (f.fecha<r.fecha_entrada OR f.fecha>=r.fecha_salida))
       )
     LIMIT 1;
    IF v_inconsistente IS NOT NULL THEN
      RAISE EXCEPTION 'La reserva % tiene fechas de estacionamiento incompletas; no se puede verificar el cupo',v_inconsistente;
    END IF;

    SELECT x.fecha INTO v_fecha_llena
      FROM unnest(v_fechas_nuevas) x(fecha)
     WHERE (SELECT count(DISTINCT r.id)::integer
              FROM public.estacionamiento_reserva_fechas f
              JOIN public.reservas r ON r.id=f.reserva_id
              JOIN public.unidades u ON u.id=r.unidad_id
             WHERE f.fecha=x.fecha AND r.id<>p_reserva_id
               AND r.usa_estacionamiento AND r.estado IN ('tentativa','confirmada','en_casa')
               AND u.edificio_id=v_edificio_id
               AND x.fecha>=r.fecha_entrada AND x.fecha<r.fecha_salida) >= v_cupos
     ORDER BY x.fecha LIMIT 1;
    IF v_fecha_llena IS NOT NULL THEN
      RAISE EXCEPTION 'Estacionamiento sin cupo para la noche %',v_fecha_llena;
    END IF;
  END IF;

  -- noches es GENERATED: se omite completamente del SET.
  UPDATE public.reservas r
     SET unidad_id=p_unidad_id,
         fecha_entrada=p_entrada,
         fecha_salida=p_salida,
         tarifa_noche=COALESCE(p_tarifa,r.tarifa_noche),
         noches_estacionamiento=cardinality(v_fechas_nuevas),
         cupo_estacionamiento=CASE WHEN p_unidad_id IS DISTINCT FROM v_reserva.unidad_id THEN NULL ELSE v_reserva.cupo_estacionamiento END,
         referencia_externa=CASE
           WHEN lower(trim(r.canal::text))='booking'
             AND NULLIF(trim(COALESCE(r.referencia_externa,'')),'') IS NULL
           THEN 'N/A' ELSE r.referencia_externa END
   WHERE r.id=p_reserva_id;

  DELETE FROM public.estacionamiento_reserva_fechas WHERE reserva_id=p_reserva_id;
  IF cardinality(v_fechas_nuevas)>0 THEN
    INSERT INTO public.estacionamiento_reserva_fechas(reserva_id,fecha)
    SELECT p_reserva_id,x.fecha FROM unnest(v_fechas_nuevas) x(fecha) ORDER BY x.fecha;
  END IF;

  SELECT count(*)::integer INTO v_count
    FROM public.estacionamiento_reserva_fechas WHERE reserva_id=p_reserva_id;
  IF v_count<>cardinality(v_fechas_nuevas) THEN
    RAISE EXCEPTION 'El movimiento no conservó las fechas de estacionamiento seleccionadas';
  END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION public.buscar_reacomodacion_cambio_unidad(p_unidad_destino uuid, p_reserva_id uuid, p_entrada date, p_salida date)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_r public.reservas%rowtype;
  v_plan jsonb;
BEGIN
  IF COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RETURN '[]'::jsonb; END IF;
  IF p_entrada IS NULL OR p_salida IS NULL OR p_salida <= p_entrada THEN RETURN '[]'::jsonb; END IF;

  SELECT r.* INTO v_r FROM public.reservas r WHERE r.id = p_reserva_id;
  IF NOT FOUND OR v_r.estado IN ('en_casa','bloqueado','cancelada','no_show','check_out') THEN
    RETURN '[]'::jsonb;
  END IF;

  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_r.unidad_id)) OR NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=p_unidad_destino)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  v_plan := public.pms_planificar_liberacion(p_unidad_destino, p_entrada, p_salida, p_reserva_id);
  IF v_plan IS NULL THEN RETURN '[]'::jsonb; END IF;

  RETURN jsonb_build_object('unidad_id', p_unidad_destino, 'plan', v_plan);
END;
$function$;

CREATE OR REPLACE FUNCTION public.guardar_fechas_estacionamiento(p_fechas date[], p_reserva_id uuid, p_permitir_sobrecupo boolean DEFAULT false)
 RETURNS TABLE(fecha date)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
DECLARE
  v_user uuid := auth.uid();
  v_reserva public.reservas%rowtype;
  v_fechas date[] := COALESCE(p_fechas, ARRAY[]::date[]);
  v_edificio_id uuid;
  v_cupos integer;
  v_reserva_inconsistente uuid;
  v_fecha_llena date;
  v_guardadas integer;
BEGIN
  IF v_user IS NULL OR COALESCE(public.pms_rol(), '') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'Sesión no válida';
  END IF;

  SELECT r.*
    INTO v_reserva
    FROM public.reservas AS r
   WHERE r.id = p_reserva_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Reserva no encontrada';
  END IF;

  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=v_reserva.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
  IF NOT (
    COALESCE(
      public.tiene_permiso_edicion(v_user, 'vehicle'),
      false
    )
    OR COALESCE(
      public.tiene_permiso_edicion(v_user, 'parking_nights'),
      false
    )
  ) THEN
    RAISE EXCEPTION
      'No tienes permiso para editar las fechas de estacionamiento';
  END IF;

  -- Rechazar fechas nulas o fuera de la estadía.
  IF EXISTS (
    SELECT 1
      FROM unnest(v_fechas) AS x(fecha)
     WHERE x.fecha IS NULL
        OR x.fecha < v_reserva.fecha_entrada
        OR x.fecha >= v_reserva.fecha_salida
  ) THEN
    RAISE EXCEPTION
      'Hay fechas nulas o fuera de la estadía';
  END IF;

  -- Rechazar fechas duplicadas.
  IF cardinality(v_fechas) <>
     (
       SELECT count(DISTINCT x.fecha)::integer
         FROM unnest(v_fechas) AS x(fecha)
     ) THEN
    RAISE EXCEPTION
      'Hay fechas de estacionamiento duplicadas';
  END IF;

  -- Obtener edificio y capacidad. El bloqueo del edificio serializa
  -- las validaciones simultáneas dentro del mismo edificio.
  SELECT u.edificio_id, e.cupos_estacionamiento
    INTO v_edificio_id, v_cupos
    FROM public.unidades AS u
    JOIN public.edificios AS e
      ON e.id = u.edificio_id
   WHERE u.id = v_reserva.unidad_id
   FOR UPDATE OF e;

  IF NOT FOUND THEN
    RAISE EXCEPTION
      'No se pudo determinar el edificio de la reserva';
  END IF;

  -- No declarar que hay cupo si otra reserva relevante tiene
  -- las fechas incompletas o fuera de su estadía.
  IF cardinality(v_fechas) > 0
     AND COALESCE(v_cupos, 0) > 0 THEN

    SELECT r.id
      INTO v_reserva_inconsistente
      FROM public.reservas AS r
      JOIN public.unidades AS u
        ON u.id = r.unidad_id
     WHERE r.id <> p_reserva_id
       AND r.usa_estacionamiento
       AND r.estado IN (
         'tentativa',
         'confirmada',
         'en_casa'
       )
       AND u.edificio_id = v_edificio_id
       AND EXISTS (
         SELECT 1
           FROM unnest(v_fechas) AS x(fecha)
          WHERE x.fecha >= r.fecha_entrada
            AND x.fecha < r.fecha_salida
       )
       AND (
         COALESCE(r.noches_estacionamiento, 0) <>
           (
             SELECT count(*)::integer
               FROM public.estacionamiento_reserva_fechas AS f
              WHERE f.reserva_id = r.id
           )
         OR EXISTS (
           SELECT 1
             FROM public.estacionamiento_reserva_fechas AS f
            WHERE f.reserva_id = r.id
              AND (
                f.fecha < r.fecha_entrada
                OR f.fecha >= r.fecha_salida
              )
         )
       )
     LIMIT 1;

    IF v_reserva_inconsistente IS NOT NULL THEN
      RAISE EXCEPTION
        'No se puede verificar el cupo: la reserva % tiene fechas de estacionamiento incompletas o fuera de su estadía. Corrígela antes de continuar.',
        v_reserva_inconsistente;
    END IF;

    -- Contar reservas por cada noche elegida, no por todas
    -- las noches comprendidas entre entrada y salida.
    SELECT x.fecha
      INTO v_fecha_llena
      FROM unnest(v_fechas) AS x(fecha)
     WHERE (
       SELECT count(DISTINCT r.id)::integer
         FROM public.estacionamiento_reserva_fechas AS f
         JOIN public.reservas AS r
           ON r.id = f.reserva_id
         JOIN public.unidades AS u
           ON u.id = r.unidad_id
        WHERE f.fecha = x.fecha
          AND r.id <> p_reserva_id
          AND r.usa_estacionamiento
          AND r.estado IN (
            'tentativa',
            'confirmada',
            'en_casa'
          )
          AND u.edificio_id = v_edificio_id
          AND x.fecha >= r.fecha_entrada
          AND x.fecha < r.fecha_salida
     ) >= v_cupos
     ORDER BY x.fecha
     LIMIT 1;

    IF v_fecha_llena IS NOT NULL
       AND NOT COALESCE(p_permitir_sobrecupo, false) THEN
      RAISE EXCEPTION
        'Sin cupos de estacionamiento para la noche % (capacidad: %).',
        v_fecha_llena,
        v_cupos;
    END IF;

  ELSIF cardinality(v_fechas) > 0
        AND COALESCE(v_cupos, 0) <= 0
        AND NOT COALESCE(p_permitir_sobrecupo, false) THEN

    RAISE EXCEPTION
      'Este edificio no tiene cupos de estacionamiento definidos. Confirma explícitamente el sobrecupo para continuar.';
  END IF;

  -- Guardar selección exacta. Si la función falla antes de terminar,
  -- PostgreSQL revierte las modificaciones de esta transacción.
  DELETE FROM public.estacionamiento_reserva_fechas
   WHERE reserva_id = p_reserva_id;

  INSERT INTO public.estacionamiento_reserva_fechas (
    reserva_id,
    fecha
  )
  SELECT p_reserva_id, x.fecha
    FROM unnest(v_fechas) AS x(fecha)
   ORDER BY x.fecha;

  UPDATE public.reservas AS r
     SET noches_estacionamiento = cardinality(v_fechas),
         usa_estacionamiento = CASE
           WHEN cardinality(v_fechas) > 0 THEN true
           ELSE COALESCE(v_reserva.usa_estacionamiento, false)
         END,
         referencia_externa = CASE
           WHEN lower(trim(r.canal::text)) = 'booking'
             AND NULLIF(
               trim(COALESCE(r.referencia_externa, '')),
               ''
             ) IS NULL
           THEN 'N/A'
           ELSE r.referencia_externa
         END
   WHERE r.id = p_reserva_id;

  -- Verificar las filas que existen realmente.
  SELECT count(*)::integer
    INTO v_guardadas
    FROM public.estacionamiento_reserva_fechas AS f
   WHERE f.reserva_id = p_reserva_id;

  IF v_guardadas <> cardinality(v_fechas) THEN
    RAISE EXCEPTION
      'Solo persistieron % de % fechas de estacionamiento',
      v_guardadas,
      cardinality(v_fechas);
  END IF;

  -- Retornar fechas reales; el frontend también hará una lectura
  -- directa posterior para contrastar el resultado.
  RETURN QUERY
  SELECT f.fecha
    FROM public.estacionamiento_reserva_fechas AS f
   WHERE f.reserva_id = p_reserva_id
   ORDER BY f.fecha;

END;
$function$;

CREATE OR REPLACE FUNCTION public.registrar_pago_airbnb(p_reserva_id uuid)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_temp'
AS $function$
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

  IF v_rol IS NULL OR v_rol NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN RAISE EXCEPTION 'Usuario sin perfil operativo activo'; END IF;
  IF NOT public.puede_ver_edificio((SELECT u.edificio_id FROM public.unidades u WHERE u.id=r.unidad_id)) THEN RAISE EXCEPTION 'No tienes acceso a esta reserva'; END IF;
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
$function$;

CREATE OR REPLACE FUNCTION public.politicas_generar_link(p_reserva_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
DECLARE
  v_rol text;
  v_codigo text;
  v_exist public.politicas_links%rowtype;
  v_intento integer;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Debes iniciar sesión'; END IF;

  SELECT p.rol::text INTO v_rol
  FROM public.perfiles p
  WHERE p.id=auth.uid() AND p.activo=true;

  IF COALESCE(v_rol,'') NOT IN ('recepcion','administracion','gerencia','sysadmin') THEN
    RAISE EXCEPTION 'No tienes permiso para generar enlaces';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.reservas r
    JOIN public.unidades u ON u.id=r.unidad_id
    WHERE r.id=p_reserva_id
      AND r.estado <> 'bloqueado'
      AND public.puede_ver_edificio(u.edificio_id)
  ) THEN
    RAISE EXCEPTION 'No tienes acceso a esta reserva';
  END IF;

  SELECT * INTO v_exist
  FROM public.politicas_links
  WHERE reserva_id=p_reserva_id
  ORDER BY creado_en DESC
  LIMIT 1;

  IF FOUND AND v_exist.aceptado_en IS NOT NULL THEN
    RETURN jsonb_build_object(
      'codigo',v_exist.codigo,'activo',false,'visitas',v_exist.visitas,
      'ultima_visita',v_exist.ultima_visita,'aceptado_en',v_exist.aceptado_en,
      'nombre_firmante',v_exist.nombre_firmante,'firma_data',v_exist.firma_data
    );
  END IF;

  IF FOUND AND v_exist.activo AND v_exist.codigo ~ '^[0-9A-F]{32}$' THEN
    RETURN jsonb_build_object(
      'codigo',v_exist.codigo,'activo',true,'visitas',v_exist.visitas,
      'ultima_visita',v_exist.ultima_visita,'aceptado_en',null,
      'nombre_firmante',null,'firma_data',null
    );
  END IF;

  FOR v_intento IN 1..5 LOOP
    v_codigo := upper(replace(gen_random_uuid()::text,'-',''));
    EXIT WHEN NOT EXISTS (SELECT 1 FROM public.politicas_links WHERE codigo=v_codigo);
    v_codigo := NULL;
  END LOOP;

  IF v_codigo IS NULL THEN RAISE EXCEPTION 'No fue posible generar un token único'; END IF;

  INSERT INTO public.politicas_links(codigo,reserva_id,creado_por)
  VALUES(v_codigo,p_reserva_id,auth.uid());

  RETURN jsonb_build_object(
    'codigo',v_codigo,'activo',true,'visitas',0,'ultima_visita',null,
    'aceptado_en',null,'nombre_firmante',null,'firma_data',null
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.solicitar_lista_negra(p_huesped_id uuid, p_motivo text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  h public.huespedes%rowtype;
  v_id uuid;
  v_rol text;
begin
  select p.rol into v_rol
  from public.perfiles p
  where p.id=auth.uid()
    and p.activo;

  if v_rol is null or v_rol not in ('recepcion','administracion','gerencia','sysadmin') then
    raise exception 'No tienes permiso para solicitar lista negra';
  end if;

  if nullif(trim(p_motivo),'') is null then
    raise exception 'El motivo es obligatorio';
  end if;

  select * into h
  from public.huespedes
  where id=p_huesped_id;

  if not found then
    raise exception 'Huésped no encontrado';
  end if;
  if not exists (select 1 from public.reservas r join public.unidades u on u.id=r.unidad_id where r.huesped_id=h.id and public.puede_ver_edificio(u.edificio_id)) then raise exception 'No tienes acceso a este huésped'; end if;

  if exists (
    select 1 from public.revisar_lista_negra_huesped(h.id)
  ) then
    raise exception 'Este huésped ya está en la lista negra';
  end if;

  if exists (
    select 1
    from public.lista_negra_solicitudes s
    where s.huesped_id=h.id
      and s.estado='pendiente'
  ) then
    raise exception 'Ya existe una solicitud pendiente para este huésped';
  end if;

  insert into public.lista_negra_solicitudes(
    huesped_id,nombre_completo,nombre_normalizado,tipo_documento,numero_documento,
    documento_normalizado,motivo,estado,solicitado_por,solicitado_en
  )
  values(
    h.id,h.nombre_completo,public.normalizar_nombre_lista_negra(h.nombre_completo),
    h.tipo_documento,h.numero_documento,h.documento_normalizado,
    trim(p_motivo),'pendiente',auth.uid(),now()
  )
  returning id into v_id;

  return v_id;
end;
$function$;

CREATE OR REPLACE FUNCTION public.politicas_estado_link(p_reserva_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
declare v_rol text; v_row public.politicas_links%rowtype;
begin
 if auth.uid() is null then raise exception 'Debes iniciar sesión'; end if;
 select rol::text into v_rol from public.perfiles where id=auth.uid() and activo=true;
 if coalesce(v_rol,'') not in ('recepcion','administracion','gerencia','sysadmin') then raise exception 'No tienes permiso'; end if;
 if not exists(select 1 from public.reservas r join public.unidades u on u.id=r.unidad_id where r.id=p_reserva_id and public.puede_ver_edificio(u.edificio_id)) then raise exception 'No tienes acceso a esta reserva'; end if;
 select * into v_row from public.politicas_links where reserva_id=p_reserva_id order by creado_en desc limit 1;
 if not found then return jsonb_build_object('generado',false,'activo',false); end if;
 return jsonb_build_object('generado',true,'codigo',v_row.codigo,'activo',v_row.activo,'visitas',v_row.visitas,'ultima_visita',v_row.ultima_visita,'aceptado_en',v_row.aceptado_en,'nombre_firmante',v_row.nombre_firmante,'firma_data',v_row.firma_data);
end $function$;

CREATE OR REPLACE FUNCTION public.politicas_publica_obtener(p_codigo text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v public.politicas_links%rowtype;
  v_res record;
  v_doc record;
  v_codigo text := upper(trim(COALESCE(p_codigo,'')));
BEGIN
  IF v_codigo !~ '^[0-9A-F]{32}$' THEN
    RETURN jsonb_build_object('ok',false,'mensaje','Este enlace ya no está disponible.');
  END IF;

  SELECT * INTO v
  FROM public.politicas_links
  WHERE codigo=v_codigo AND activo=true AND aceptado_en IS NULL
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok',false,'mensaje','Este enlace ya no está disponible.');
  END IF;

  UPDATE public.politicas_links
  SET visitas=visitas+1, ultima_visita=now()
  WHERE codigo=v.codigo;

  SELECT rs.fecha_entrada,rs.fecha_salida,rs.adultos,rs.menores,
         un.codigo AS unidad,ed.nombre AS edificio
  INTO v_res
  FROM public.reservas rs
  JOIN public.unidades un ON un.id=rs.unidad_id
  JOIN public.edificios ed ON ed.id=un.edificio_id
  WHERE rs.id=v.reserva_id;

  SELECT contenido_es,contenido_en INTO v_doc
  FROM public.politicas_documento WHERE id=true;

  RETURN jsonb_build_object(
    'ok',true,'contenido_es',v_doc.contenido_es,'contenido_en',v_doc.contenido_en,
    'fecha_entrada',v_res.fecha_entrada,'fecha_salida',v_res.fecha_salida,
    'unidad',v_res.unidad,'edificio',v_res.edificio,
    'adultos',v_res.adultos,'menores',v_res.menores
  );
END;
$function$;

CREATE OR REPLACE FUNCTION public.politicas_publica_aceptar(p_codigo text, p_nombre text, p_firma text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  v_codigo text := upper(trim(COALESCE(p_codigo,'')));
  v_nombre text := trim(COALESCE(p_nombre,''));
  v_count integer;
BEGIN
  IF v_codigo !~ '^[0-9A-F]{32}$' THEN
    RETURN jsonb_build_object('ok',false,'mensaje','El enlace ya no está disponible.');
  END IF;
  IF length(v_nombre)<3 OR length(v_nombre)>140 THEN
    RAISE EXCEPTION 'Ingresa tu nombre completo';
  END IF;
  IF p_firma IS NULL OR length(p_firma)<100 OR length(p_firma)>1800000 OR p_firma !~ '^data:image/png;base64,' THEN
    RAISE EXCEPTION 'La firma no es válida';
  END IF;

  UPDATE public.politicas_links
  SET activo=false,aceptado_en=now(),nombre_firmante=v_nombre,firma_data=p_firma
  WHERE codigo=v_codigo AND activo=true AND aceptado_en IS NULL;

  GET DIAGNOSTICS v_count=ROW_COUNT;
  IF v_count=0 THEN
    RETURN jsonb_build_object('ok',false,'mensaje','El enlace ya fue utilizado o desactivado.');
  END IF;

  RETURN jsonb_build_object('ok',true,'aceptado_en',now());
END;
$function$;

CREATE OR REPLACE FUNCTION public.pms_puede_ver_grupo(p_grupo_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
  SELECT auth.uid() IS NOT NULL
     AND public.pms_rol() IN ('recepcion','administracion','gerencia','sysadmin')
     AND (
       public.pms_rol() IN ('administracion','gerencia','sysadmin')
       OR EXISTS (
         SELECT 1
         FROM public.reserva_grupos g
         WHERE g.id = p_grupo_id
           AND g.creado_por = auth.uid()
           AND NOT EXISTS (
             SELECT 1 FROM public.reserva_grupo_miembros gm
             WHERE gm.grupo_id = g.id
           )
       )
       OR EXISTS (
         SELECT 1
         FROM public.reserva_grupo_miembros gm
         JOIN public.reservas r ON r.id = gm.reserva_id
         JOIN public.unidades u ON u.id = r.unidad_id
         WHERE gm.grupo_id = p_grupo_id
           AND public.puede_ver_edificio(u.edificio_id)
       )
     );
$function$;

CREATE OR REPLACE FUNCTION public.huespedes_panel()
 RETURNS TABLE(huesped_id uuid, uid_huesped text, nombre_completo text, tipo_documento text, numero_documento text, telefono text, correo text, nacionalidad text, ciudad_origen text, fecha_nacimiento date, es_vip boolean, creado_en timestamp with time zone, creado_por uuid, edificio_id uuid, edificio text, reservas_edificio bigint, en_casa boolean, estadias bigint, cancelaciones bigint, no_shows bigint, ultima_estadia date, lista_negra_activa boolean)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  with rv as (
    select distinct
      r.huesped_id,
      u.edificio_id,
      e.nombre as edificio
    from public.reservas r
    join public.unidades u on u.id=r.unidad_id
    join public.edificios e on e.id=u.edificio_id
    where r.estado in ('check_out','en_casa') AND EXISTS (SELECT 1 FROM public.perfiles p0 WHERE p0.id=auth.uid() AND p0.activo AND p0.rol::text IN ('recepcion','administracion','gerencia','sysadmin','system_admin','systemadmin'))
      and (
        exists (
          select 1 from public.perfiles p
          where p.id=auth.uid()
            and p.activo
            and p.rol in ('administracion','gerencia','sysadmin')
        )
        or exists (
          select 1 from public.perfiles_edificios pe
          where pe.perfil_id=auth.uid()
            and pe.edificio_id=u.edificio_id
        )
      )
  )
  select
    h.id,
    h.uid_huesped,
    h.nombre_completo,
    h.tipo_documento,
    h.numero_documento,
    h.telefono,
    h.correo,
    h.nacionalidad,
    h.ciudad_origen,
    h.fecha_nacimiento,
    h.es_vip,
    h.creado_en,
    h.creado_por,
    rv.edificio_id,
    rv.edificio,
    (
      select count(*)
      from public.reservas r2
      join public.unidades u2 on u2.id=r2.unidad_id
      where r2.huesped_id=h.id
        and u2.edificio_id=rv.edificio_id
        and r2.estado in ('check_out','en_casa')
    ) as reservas_edificio,
    exists (
      select 1
      from public.reservas rc
      join public.unidades uc on uc.id=rc.unidad_id
      where rc.huesped_id=h.id
        and uc.edificio_id=rv.edificio_id
        and rc.estado='en_casa'
    ) as en_casa,
    coalesce(s.estadias,0),
    coalesce(s.cancelaciones,0),
    coalesce(s.no_shows,0),
    s.ultima_estadia,
    exists (
      select 1
      from public.lista_negra l
      where l.activo
        and (
          (
            nullif(trim(h.documento_normalizado),'') is not null
            and nullif(trim(l.documento_normalizado),'') is not null
            and h.documento_normalizado=l.documento_normalizado
          )
          or (
            nullif(trim(h.numero_documento),'') is not null
            and nullif(trim(l.numero_documento),'') is not null
            and lower(trim(h.numero_documento))=lower(trim(l.numero_documento))
          )
          or (
            nullif(trim(h.documento_normalizado),'') is null
            and nullif(trim(h.numero_documento),'') is null
            and public.normalizar_nombre_lista_negra(h.nombre_completo)
                = public.normalizar_nombre_lista_negra(l.nombre_completo)
          )
        )
    ) as lista_negra_activa
  from rv
  join public.huespedes h on h.id=rv.huesped_id
  left join public.resumen_huesped s on s.huesped_id=h.id
  order by rv.edificio, h.nombre_completo;
$function$;

CREATE OR REPLACE FUNCTION public.buscar_disponibilidad_global(p_entrada date, p_salida date)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
DECLARE
  v_user uuid := auth.uid();
  v_rol text;
  v_item record;
  v_plan jsonb;
  v_target_id uuid;
  v_target record;
  v_result jsonb := '[]'::jsonb;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'Sesión no válida';
  END IF;

  SELECT lower(trim(p.rol::text))
    INTO v_rol
    FROM public.perfiles p
   WHERE p.id = v_user
     AND p.activo = true;

  IF v_rol IS NULL OR v_rol NOT IN ('recepcion','administracion','gerencia','sysadmin','system_admin','systemadmin') THEN
    RAISE EXCEPTION 'Usuario sin perfil de personal activo';
  END IF;

  IF p_entrada IS NULL OR p_salida IS NULL OR p_salida <= p_entrada THEN
    RAISE EXCEPTION 'La fecha de salida debe ser posterior a la fecha de entrada';
  END IF;

  FOR v_item IN
    SELECT
      u.id AS unidad_id,
      u.codigo::text AS unidad,
      u.edificio_id,
      e.nombre AS edificio,
      e.orden AS edificio_orden,
      tu.id AS categoria_id,
      tu.nombre::text AS categoria,
      (
        v_rol IN ('administracion','gerencia','sysadmin','system_admin','systemadmin')
        OR EXISTS (
          SELECT 1 FROM public.perfiles_edificios pe
           WHERE pe.perfil_id = v_user AND pe.edificio_id = u.edificio_id
        )
      ) AS acceso
    FROM public.unidades u
    JOIN public.edificios e ON e.id = u.edificio_id AND e.activo = true
    JOIN public.tipos_unidad tu ON tu.id = u.tipo_unidad_id
    WHERE u.activo = true AND (v_rol IN ('administracion','gerencia','sysadmin') OR EXISTS (SELECT 1 FROM public.perfiles_edificios pe WHERE pe.perfil_id=v_user AND pe.edificio_id=u.edificio_id))
      AND NOT EXISTS (
        SELECT 1 FROM public.reservas r
         WHERE r.unidad_id = u.id
           AND r.fecha_entrada < p_salida
           AND r.fecha_salida > p_entrada
           AND r.estado NOT IN ('cancelada','no_show')
      )
    ORDER BY acceso DESC, e.orden NULLS LAST, e.nombre, tu.nombre, u.orden NULLS LAST, u.codigo
  LOOP
    v_result := v_result || jsonb_build_array(jsonb_build_object(
      'edificio_id', v_item.edificio_id,
      'edificio', v_item.edificio,
      'edificio_orden', v_item.edificio_orden,
      'categoria_id', v_item.categoria_id,
      'categoria', v_item.categoria,
      'unidad_id', v_item.unidad_id,
      'unidad', v_item.unidad,
      'tipo', 'directa',
      'plan', '[]'::jsonb,
      'acceso', v_item.acceso
    ));
  END LOOP;

  FOR v_item IN
    SELECT DISTINCT u.edificio_id, e.nombre AS edificio, e.orden AS edificio_orden,
           u.tipo_unidad_id AS categoria_id, tu.nombre AS categoria,
           (
             v_rol IN ('administracion','gerencia','sysadmin','system_admin','systemadmin')
             OR EXISTS (
               SELECT 1 FROM public.perfiles_edificios pe
                WHERE pe.perfil_id = v_user AND pe.edificio_id = u.edificio_id
             )
           ) AS acceso
      FROM public.unidades u
      JOIN public.edificios e ON e.id = u.edificio_id AND e.activo = true
      JOIN public.tipos_unidad tu ON tu.id = u.tipo_unidad_id
     WHERE u.activo = true AND (v_rol IN ('administracion','gerencia','sysadmin') OR EXISTS (SELECT 1 FROM public.perfiles_edificios pe WHERE pe.perfil_id=v_user AND pe.edificio_id=u.edificio_id))
       AND NOT EXISTS (
         SELECT 1
           FROM public.unidades libre
          WHERE libre.activo = true
            AND libre.edificio_id = u.edificio_id
            AND libre.tipo_unidad_id = u.tipo_unidad_id
            AND NOT EXISTS (
              SELECT 1 FROM public.reservas r
               WHERE r.unidad_id = libre.id
                 AND r.fecha_entrada < p_salida
                 AND r.fecha_salida > p_entrada
                 AND r.estado NOT IN ('cancelada','no_show')
            )
       )
     ORDER BY acceso DESC, e.orden NULLS LAST, e.nombre, tu.nombre
  LOOP
    v_plan := public.buscar_reacomodacion(
      p_edificio_id => v_item.edificio_id,
      p_tipo_unidad_id => v_item.categoria_id,
      p_entrada => p_entrada,
      p_salida => p_salida
    );

    v_target_id := NULLIF(v_plan->>'unidad_id','')::uuid;
    IF v_target_id IS NULL THEN CONTINUE; END IF;

    SELECT u.id AS unidad_id, u.codigo::text AS unidad,
           u.edificio_id, e.nombre AS edificio, e.orden AS edificio_orden,
           tu.id AS categoria_id, tu.nombre::text AS categoria
      INTO v_target
      FROM public.unidades u
      JOIN public.edificios e ON e.id = u.edificio_id
      JOIN public.tipos_unidad tu ON tu.id = u.tipo_unidad_id
     WHERE u.id = v_target_id AND u.activo = true;

    IF NOT FOUND THEN CONTINUE; END IF;

    v_result := v_result || jsonb_build_array(jsonb_build_object(
      'edificio_id', v_target.edificio_id,
      'edificio', v_target.edificio,
      'edificio_orden', v_target.edificio_orden,
      'categoria_id', v_target.categoria_id,
      'categoria', v_target.categoria,
      'unidad_id', v_target.unidad_id,
      'unidad', v_target.unidad,
      'tipo', 'reacomodacion',
      'plan', COALESCE(v_plan->'plan','[]'::jsonb),
      'acceso', v_item.acceso
    ));
  END LOOP;

  RETURN v_result;
END;
$function$;

-- Revoke public execution from privileged RPCs and preserve authenticated use.
DO $$
DECLARE f record;
BEGIN
 FOR f IN
  SELECT p.oid::regprocedure signature
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public' AND p.prokind='f' AND p.prosecdef
    AND has_function_privilege('anon',p.oid,'EXECUTE')
    AND p.oid NOT IN (
      'public.politicas_publica_obtener(text)'::regprocedure,
      'public.politicas_publica_aceptar(text,text,text)'::regprocedure
    )
 LOOP
  EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon',f.signature);
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated, service_role',f.signature);
 END LOOP;
END $$;

GRANT EXECUTE ON FUNCTION public.politicas_publica_obtener(text) TO anon,authenticated;
GRANT EXECUTE ON FUNCTION public.politicas_publica_aceptar(text,text,text) TO anon,authenticated;
REVOKE ALL ON FUNCTION public.pms_puede_ver_grupo(uuid) FROM PUBLIC,anon;
GRANT EXECUTE ON FUNCTION public.pms_puede_ver_grupo(uuid) TO authenticated,service_role;

REVOKE EXECUTE ON FUNCTION public.mover_reserva(uuid,uuid,date,date,integer) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.pms_crear_reserva_con_reacomodacion(uuid,uuid,date,date,estado_reserva,canal_reserva,text,integer,integer,integer,boolean,integer,text,text,jsonb) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.pms_revisar_lista_negra(text,text) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.recalcular_estado_pago(uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.pms_plan_extension_move(uuid,uuid,integer,uuid[],uuid[]) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.ranking_categoria_unidad(uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.noches_estacionamiento_reserva(uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public._borrar_dependientes(regclass,uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public._borrar_reserva(uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.auditar_cambio() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.registrar_auditoria() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.crear_tarea_limpieza() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.pms_buscar_reacomodacion(uuid,uuid,date,date,uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.mis_tareas_limpieza() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.buzon_enviar(text,text,uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.buzon_guardar_permisos(uuid,boolean,boolean) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.buzon_listar() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.buzon_marcar_leido(uuid) FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.buzon_limpiar_bandeja() FROM PUBLIC,anon,authenticated;
REVOKE EXECUTE ON FUNCTION public.tiene_permiso_edicion(uuid,text) FROM PUBLIC,anon,authenticated;

DROP POLICY IF EXISTS "pms_scope_acompanantes" ON public.acompanantes;
CREATE POLICY "pms_scope_acompanantes" ON public.acompanantes AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = acompanantes.reserva_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = acompanantes.reserva_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_cargos" ON public.cargos;
CREATE POLICY "pms_scope_cargos" ON public.cargos AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = cargos.reserva_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = cargos.reserva_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_ranking" ON public.categoria_ranking_edificio;
CREATE POLICY "pms_scope_ranking" ON public.categoria_ranking_edificio AS RESTRICTIVE FOR SELECT TO authenticated
USING (((pms_rol() IS NOT NULL) AND puede_ver_edificio(edificio_id)));

DROP POLICY IF EXISTS "pms_scope_edificios" ON public.edificios;
CREATE POLICY "pms_scope_edificios" ON public.edificios AS RESTRICTIVE FOR SELECT TO authenticated
USING (((pms_rol() IS NOT NULL) AND puede_ver_edificio(id)));

DROP POLICY IF EXISTS "pms_scope_estacionamiento_fechas" ON public.estacionamiento_reserva_fechas;
CREATE POLICY "pms_scope_estacionamiento_fechas" ON public.estacionamiento_reserva_fechas AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = estacionamiento_reserva_fechas.reserva_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = estacionamiento_reserva_fechas.reserva_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_garantia_fechas" ON public.garantia_fechas;
CREATE POLICY "pms_scope_garantia_fechas" ON public.garantia_fechas AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = garantia_fechas.unidad_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = garantia_fechas.unidad_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_huespedes" ON public.huespedes;
CREATE POLICY "pms_scope_huespedes" ON public.huespedes AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (((creado_por = auth.uid()) AND (NOT (EXISTS ( SELECT 1
   FROM reservas r
  WHERE (r.huesped_id = huespedes.id))))) OR (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.huesped_id = huespedes.id) AND puede_ver_edificio(u.edificio_id)))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (((creado_por = auth.uid()) AND (NOT (EXISTS ( SELECT 1
   FROM reservas r
  WHERE (r.huesped_id = huespedes.id))))) OR (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.huesped_id = huespedes.id) AND puede_ver_edificio(u.edificio_id)))))));

DROP POLICY IF EXISTS "pms_scope_limpieza" ON public.limpieza;
CREATE POLICY "pms_scope_limpieza" ON public.limpieza AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['limpieza'::text, 'recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = limpieza.unidad_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['limpieza'::text, 'recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = limpieza.unidad_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_lista_negra" ON public.lista_negra;
CREATE POLICY "pms_scope_lista_negra" ON public.lista_negra AS RESTRICTIVE FOR SELECT TO authenticated
USING ((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])));

DROP POLICY IF EXISTS "pms_scope_notas_huesped" ON public.notas_huesped;
CREATE POLICY "pms_scope_notas_huesped" ON public.notas_huesped AS RESTRICTIVE FOR ALL TO "authenticated"
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (((reserva_id IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = notas_huesped.reserva_id) AND puede_ver_edificio(u.edificio_id))))) OR ((reserva_id IS NULL) AND (EXISTS ( SELECT 1
   FROM huespedes h
  WHERE (h.id = notas_huesped.huesped_id)))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (((reserva_id IS NOT NULL) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = notas_huesped.reserva_id) AND puede_ver_edificio(u.edificio_id))))) OR ((reserva_id IS NULL) AND (EXISTS ( SELECT 1
   FROM huespedes h
  WHERE (h.id = notas_huesped.huesped_id)))))));
DROP POLICY IF EXISTS "pms_scope_pagos" ON public.pagos;
CREATE POLICY "pms_scope_pagos" ON public.pagos AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = pagos.reserva_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = pagos.reserva_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "PMS usuarios autenticados pagos compartidos" ON public.pagos_compartidos;
CREATE POLICY "PMS usuarios autenticados pagos compartidos" ON public.pagos_compartidos AS PERMISSIVE FOR ALL TO authenticated
USING (pms_puede_ver_grupo(grupo_id))
WITH CHECK (pms_puede_ver_grupo(grupo_id));

DROP POLICY IF EXISTS "PMS usuarios autenticados distribucion pagos compartidos" ON public.pagos_compartidos_distribucion;
CREATE POLICY "PMS usuarios autenticados distribucion pagos compartidos" ON public.pagos_compartidos_distribucion AS PERMISSIVE FOR ALL TO authenticated
USING ((EXISTS ( SELECT 1
   FROM (((pagos_compartidos pc
     JOIN reserva_grupo_miembros gm ON (((gm.grupo_id = pc.grupo_id) AND (gm.reserva_id = pagos_compartidos_distribucion.reserva_id))))
     JOIN reservas r ON ((r.id = gm.reserva_id)))
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((pc.id = pagos_compartidos_distribucion.pago_compartido_id) AND pms_puede_ver_grupo(pc.grupo_id) AND puede_ver_edificio(u.edificio_id)))))
WITH CHECK ((EXISTS ( SELECT 1
   FROM (((pagos_compartidos pc
     JOIN reserva_grupo_miembros gm ON (((gm.grupo_id = pc.grupo_id) AND (gm.reserva_id = pagos_compartidos_distribucion.reserva_id))))
     JOIN reservas r ON ((r.id = gm.reserva_id)))
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((pc.id = pagos_compartidos_distribucion.pago_compartido_id) AND pms_puede_ver_grupo(pc.grupo_id) AND puede_ver_edificio(u.edificio_id)))));

DROP POLICY IF EXISTS "PMS usuarios autenticados reserva grupo miembros" ON public.reserva_grupo_miembros;
CREATE POLICY "PMS usuarios autenticados reserva grupo miembros" ON public.reserva_grupo_miembros AS PERMISSIVE FOR ALL TO authenticated
USING ((pms_puede_ver_grupo(grupo_id) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = reserva_grupo_miembros.reserva_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK ((pms_puede_ver_grupo(grupo_id) AND (EXISTS ( SELECT 1
   FROM (reservas r
     JOIN unidades u ON ((u.id = r.unidad_id)))
  WHERE ((r.id = reserva_grupo_miembros.reserva_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "PMS crear grupos propios" ON public.reserva_grupos;
CREATE POLICY "PMS crear grupos propios" ON public.reserva_grupos AS PERMISSIVE FOR INSERT TO authenticated
WITH CHECK (((creado_por = auth.uid()) AND (pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text]))));

DROP POLICY IF EXISTS "PMS usuarios autenticados reserva grupos" ON public.reserva_grupos;
CREATE POLICY "PMS usuarios autenticados reserva grupos" ON public.reserva_grupos AS PERMISSIVE FOR ALL TO authenticated
USING (pms_puede_ver_grupo(id))
WITH CHECK (pms_puede_ver_grupo(id));

DROP POLICY IF EXISTS "pms_scope_reservas" ON public.reservas;
CREATE POLICY "pms_scope_reservas" ON public.reservas AS RESTRICTIVE FOR ALL TO authenticated
USING (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = reservas.unidad_id) AND puede_ver_edificio(u.edificio_id))))))
WITH CHECK (((pms_rol() = ANY (ARRAY['recepcion'::text, 'administracion'::text, 'gerencia'::text, 'sysadmin'::text, 'system_admin'::text, 'systemadmin'::text])) AND (EXISTS ( SELECT 1
   FROM unidades u
  WHERE ((u.id = reservas.unidad_id) AND puede_ver_edificio(u.edificio_id))))));

DROP POLICY IF EXISTS "pms_scope_unidades" ON public.unidades;
CREATE POLICY "pms_scope_unidades" ON public.unidades AS RESTRICTIVE FOR SELECT TO authenticated
USING (((pms_rol() IS NOT NULL) AND puede_ver_edificio(edificio_id)));

-- Financial data integrity: restrict deletes to finance managers and disallow direct amount edits.
DROP POLICY IF EXISTS cargos_sin_borrado ON public.cargos;
CREATE POLICY cargos_sin_borrado ON public.cargos AS RESTRICTIVE FOR DELETE TO authenticated
USING (public.pms_rol() IN ('administracion','gerencia','sysadmin') AND EXISTS (SELECT 1 FROM public.reservas r JOIN public.unidades u ON u.id=r.unidad_id WHERE r.id=cargos.reserva_id AND public.puede_ver_edificio(u.edificio_id)));
DROP POLICY IF EXISTS pagos_sin_borrado ON public.pagos;
CREATE POLICY pagos_sin_borrado ON public.pagos AS RESTRICTIVE FOR DELETE TO authenticated
USING (public.pms_rol() IN ('administracion','gerencia','sysadmin') AND EXISTS (SELECT 1 FROM public.reservas r JOIN public.unidades u ON u.id=r.unidad_id WHERE r.id=pagos.reserva_id AND public.puede_ver_edificio(u.edificio_id)));
DROP POLICY IF EXISTS pms_delete_pagos_compartidos ON public.pagos_compartidos;
CREATE POLICY pms_delete_pagos_compartidos ON public.pagos_compartidos AS RESTRICTIVE FOR DELETE TO authenticated
USING (public.pms_rol() IN ('administracion','gerencia','sysadmin') AND public.pms_puede_ver_grupo(grupo_id));
DROP POLICY IF EXISTS pms_delete_pagos_compartidos_distribucion ON public.pagos_compartidos_distribucion;
CREATE POLICY pms_delete_pagos_compartidos_distribucion ON public.pagos_compartidos_distribucion AS RESTRICTIVE FOR DELETE TO authenticated
USING (public.pms_rol() IN ('administracion','gerencia','sysadmin') AND EXISTS (
 SELECT 1 FROM public.pagos_compartidos pc
 JOIN public.reserva_grupo_miembros gm ON gm.grupo_id=pc.grupo_id AND gm.reserva_id=pagos_compartidos_distribucion.reserva_id
 JOIN public.reservas r ON r.id=gm.reserva_id JOIN public.unidades u ON u.id=r.unidad_id
 WHERE pc.id=pagos_compartidos_distribucion.pago_compartido_id
 AND public.pms_puede_ver_grupo(pc.grupo_id) AND public.puede_ver_edificio(u.edificio_id)
));
REVOKE UPDATE ON TABLE public.pagos FROM PUBLIC,anon,authenticated;
REVOKE UPDATE ON TABLE public.cargos FROM PUBLIC,anon,authenticated;
REVOKE UPDATE ON TABLE public.pagos_compartidos_distribucion FROM PUBLIC,anon,authenticated;
REVOKE UPDATE ON TABLE public.pagos_compartidos FROM PUBLIC,anon,authenticated;
GRANT UPDATE (grupo_id) ON TABLE public.pagos_compartidos TO authenticated;

UPDATE storage.buckets
 SET file_size_limit=10485760,
     allowed_mime_types=ARRAY['image/jpeg','image/png','image/webp','image/avif']::text[]
 WHERE id='fotos_unidades';

ALTER FUNCTION public.poner_actualizado_en() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.copiar_datos_huesped() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.trg_recalcular_pago_hijo() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.trg_recalcular_pago_reserva() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.validar_cupo_estacionamiento() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.calcular_recargo_horario(time without time zone,time without time zone,time without time zone,integer) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.cancelar_reserva(uuid,text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.normalizar_usuario(text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.poner_usuario() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.pedir_limpieza(uuid,text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.buscar_reservas(text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.proteger_rol_perfil() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.omitir_garantia(uuid,text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.reactivar_garantia(uuid) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.marcar_no_show(uuid,text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.hacer_check_out(uuid,text,text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.normalizar_nombre_lista_negra(text) SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.validar_reserva_pms_precio_estacionamiento() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.pms_validar_codigo_booking() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.pms_validar_noches_estacionamiento() SET search_path=pg_catalog,public,auth,pg_temp;
ALTER FUNCTION public.reclamos_sugerencias_set_actualizado_en() SET search_path=pg_catalog,public,auth,pg_temp;

COMMIT;

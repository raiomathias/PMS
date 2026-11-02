-- PMS v3.9.1 · Endurecimiento final de notificaciones Booking.com
-- Mantiene el historial completo en el Buzón, limita los datos por edificio
-- y registra cada acción con el usuario autenticado.

create or replace function public.pms_booking_notif_access(p_edificio uuid)
returns boolean
language sql stable security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
 select exists(
   select 1 from public.perfiles p
   where p.id=auth.uid() and p.activo
     and lower(trim(p.rol::text)) in('gerencia','sysadmin','system_admin','systemadmin')
 ) or exists(
   select 1 from public.perfiles_edificios pe
   join public.perfiles p on p.id=pe.perfil_id
   where p.id=auth.uid() and p.activo and pe.edificio_id=p_edificio
 )
$$;

create or replace function public.pms_booking_no_show_trigger()
returns trigger language plpgsql security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
declare v_edificio uuid;v_unidad text;v_nombre text;v_notif uuid;v_actor uuid;
begin
 if new.estado::text='no_show' and new.canal::text='booking'
    and (tg_op='INSERT' or old.estado::text is distinct from 'no_show') then
  v_actor:=coalesce(new.no_show_por,auth.uid());
  select u.edificio_id,u.codigo,
         coalesce(nullif(new.huesped_nombre_copia,''),h.nombre_completo,'Huésped')
    into v_edificio,v_unidad,v_nombre
    from public.unidades u left join public.huespedes h on h.id=new.huesped_id
   where u.id=new.unidad_id;
  if v_edificio is not null then
   insert into public.notificaciones_booking_no_show
    (reserva_id,edificio_id,fecha_entrada,unidad_codigo,huesped_nombre,creada_por)
   values(new.id,v_edificio,new.fecha_entrada,coalesce(v_unidad,'—'),coalesce(v_nombre,'Huésped'),v_actor)
   on conflict(reserva_id) do nothing returning id into v_notif;
   if v_notif is not null then
    insert into public.auditoria(tabla,registro_id,accion,datos_anteriores,datos_nuevos,usuario_id,fecha)
    values('notificaciones_booking_no_show',v_notif,'INSERT',null,
      jsonb_build_object('reserva_id',new.id,'edificio_id',v_edificio,
       'fecha_entrada',new.fecha_entrada,'unidad',v_unidad,'huesped',v_nombre,
       'estado','pendiente','hora_programada',
       (select valor from public.configuracion where clave='booking_no_show_hora'),
       'notificacion_origen','PMS No-show Booking.com'),v_actor,now());
   end if;
  end if;
 end if;
 return new;
end $$;

create or replace function public.pms_booking_notif_list()
returns table(
 id uuid,reserva_id uuid,edificio_id uuid,edificio text,unidad text,huesped text,
 fecha_entrada date,estado text,creada_en timestamptz,marcado_en timestamptz,
 marcado_por uuid,marcado_por_nombre text,mensaje text,
 notificaciones_activo boolean,hora_programada text
)
language plpgsql security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
declare v_hora text;v_activo text;v_template text;
begin
 if auth.uid() is null then raise exception 'Sesión no válida';end if;
 select valor into v_activo from public.configuracion where clave='booking_no_show_notificaciones_activo';
 select valor into v_hora from public.configuracion where clave='booking_no_show_hora';
 select valor into v_template from public.configuracion where clave='booking_no_show_mensaje';
 return query
 select n.id,n.reserva_id,n.edificio_id,e.nombre,n.unidad_codigo,n.huesped_nombre,
  n.fecha_entrada,n.estado,n.creada_en,n.marcado_en,n.marcado_por,p.nombre_completo,
  replace(replace(replace(replace(coalesce(v_template,
   'Hoy corresponde marcar No-show en Booking.com: {huesped} · {edificio} · Unidad {unidad} · Entrada {fecha}.'),
   '{huesped}',n.huesped_nombre),'{edificio}',e.nombre),'{unidad}',n.unidad_codigo),
   '{fecha}',to_char(n.fecha_entrada,'DD-MM-YYYY')),
  coalesce(v_activo,'true')='true',coalesce(v_hora,'10:00')
 from public.notificaciones_booking_no_show n
 join public.edificios e on e.id=n.edificio_id
 left join public.perfiles p on p.id=n.marcado_por
 where public.pms_booking_notif_access(n.edificio_id)
 order by n.fecha_entrada desc,n.creada_en desc;
end $$;

create or replace function public.pms_booking_notif_mark(p_id uuid)
returns void language plpgsql security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
declare n public.notificaciones_booking_no_show%rowtype;v_user uuid;v_name text;
begin
 v_user:=auth.uid();if v_user is null then raise exception 'Sesión no válida';end if;
 select * into n from public.notificaciones_booking_no_show where id=p_id for update;
 if not found then raise exception 'Notificación no encontrada';end if;
 if not public.pms_booking_notif_access(n.edificio_id) then raise exception 'Sin acceso a este edificio';end if;
 if n.estado='marcado_booking' then return;end if;
 select nombre_completo into v_name from public.perfiles where id=v_user;
 update public.notificaciones_booking_no_show
 set estado='marcado_booking',marcado_en=now(),marcado_por=v_user,updated_at=now()
 where id=p_id;
 insert into public.auditoria(tabla,registro_id,accion,datos_anteriores,datos_nuevos,usuario_id,fecha)
 values('notificaciones_booking_no_show',p_id,'UPDATE',to_jsonb(n),
  jsonb_build_object('estado','marcado_booking','marcado_en',now(),
   'marcado_por',v_user,'marcado_por_nombre',v_name,'reserva_id',n.reserva_id,
   'edificio_id',n.edificio_id),v_user,now());
end $$;

create or replace function public.pms_booking_notif_audit_action(p_id uuid,p_accion text)
returns void language plpgsql security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
declare n public.notificaciones_booking_no_show%rowtype;v_user uuid;v_name text;
begin
 v_user:=auth.uid();if v_user is null then raise exception 'Sesión no válida';end if;
 if p_accion not in('popup_visto','popup_cerrado','chat_abierto') then raise exception 'Acción no permitida';end if;
 select * into n from public.notificaciones_booking_no_show where id=p_id;
 if not found then raise exception 'Notificación no encontrada';end if;
 if not public.pms_booking_notif_access(n.edificio_id) then raise exception 'Sin acceso a este edificio';end if;
 select nombre_completo into v_name from public.perfiles where id=v_user;
 insert into public.auditoria(tabla,registro_id,accion,datos_anteriores,datos_nuevos,usuario_id,fecha)
 values('notificaciones_booking_no_show',p_id,'UPDATE',jsonb_build_object('estado',n.estado),
  jsonb_build_object('accion',p_accion,'usuario_id',v_user,'usuario_nombre',v_name,
   'reserva_id',n.reserva_id,'edificio_id',n.edificio_id,'estado_actual',n.estado),v_user,now());
end $$;

create or replace function public.pms_booking_notif_config(p_activo boolean,p_hora text,p_mensaje text)
returns void language plpgsql security definer
set search_path=pg_catalog,public,auth,pg_temp
as $$
declare v_user uuid;v_prev_activo text;v_prev_hora text;v_prev_msg text;
begin
 v_user:=auth.uid();
 if v_user is null or not exists(select 1 from public.perfiles
  where id=v_user and activo and lower(trim(rol::text)) in('gerencia','sysadmin','system_admin','systemadmin'))
 then raise exception 'Solo Gerencia o SysAdmin';end if;
 if p_hora !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$' then raise exception 'Hora debe ser HH:MM';end if;
 if length(trim(p_mensaje)) not between 1 and 1000 then raise exception 'La plantilla debe tener entre 1 y 1000 caracteres';end if;
 select valor into v_prev_activo from public.configuracion where clave='booking_no_show_notificaciones_activo';
 select valor into v_prev_hora from public.configuracion where clave='booking_no_show_hora';
 select valor into v_prev_msg from public.configuracion where clave='booking_no_show_mensaje';
 update public.configuracion set valor=p_activo::text,actualizado_por=v_user,actualizado_en=now() where clave='booking_no_show_notificaciones_activo';
 update public.configuracion set valor=p_hora,actualizado_por=v_user,actualizado_en=now() where clave='booking_no_show_hora';
 update public.configuracion set valor=p_mensaje,actualizado_por=v_user,actualizado_en=now() where clave='booking_no_show_mensaje';
 insert into public.auditoria(tabla,registro_id,accion,datos_anteriores,datos_nuevos,usuario_id,fecha)
 values('configuracion',null,'UPDATE',
  jsonb_build_object('activo',v_prev_activo,'hora',v_prev_hora,'mensaje',v_prev_msg),
  jsonb_build_object('activo',p_activo,'hora',p_hora,'mensaje',p_mensaje),v_user,now());
end $$;

revoke execute on function public.pms_booking_notif_access(uuid) from public,anon;
revoke execute on function public.pms_booking_notif_list() from public,anon;
revoke execute on function public.pms_booking_notif_mark(uuid) from public,anon;
revoke execute on function public.pms_booking_notif_config(boolean,text,text) from public,anon;
revoke execute on function public.pms_booking_notif_audit_action(uuid,text) from public,anon;
revoke execute on function public.pms_booking_no_show_trigger() from public,anon,authenticated;
grant execute on function public.pms_booking_notif_access(uuid) to authenticated;
grant execute on function public.pms_booking_notif_list() to authenticated;
grant execute on function public.pms_booking_notif_mark(uuid) to authenticated;
grant execute on function public.pms_booking_notif_config(boolean,text,text) to authenticated;
grant execute on function public.pms_booking_notif_audit_action(uuid,text) to authenticated;
grant select on public.notificaciones_booking_no_show to authenticated;
drop policy if exists notif_booking_no_show_select_access on public.notificaciones_booking_no_show;
create policy notif_booking_no_show_select_access on public.notificaciones_booking_no_show
 for select to authenticated using (public.pms_booking_notif_access(edificio_id));

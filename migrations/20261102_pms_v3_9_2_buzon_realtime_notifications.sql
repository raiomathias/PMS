-- PMS v3.9.2 · Realtime para Notificaciones del Sistema
-- Permite que cambios de estado y nuevas notificaciones se reflejen sin polling.
do $$
begin
 if not exists(
  select 1 from pg_publication_tables
  where pubname='supabase_realtime'
    and schemaname='public'
    and tablename='notificaciones_booking_no_show'
 ) then
  alter publication supabase_realtime add table public.notificaciones_booking_no_show;
 end if;
end $$;

-- PMS v3.9.1 · Apply direct table RLS based on assigned building access
grant execute on function public.pms_booking_notif_access(uuid) to authenticated;
drop policy if exists notif_booking_no_show_select_access on public.notificaciones_booking_no_show;
create policy notif_booking_no_show_select_access on public.notificaciones_booking_no_show
for select to authenticated using (public.pms_booking_notif_access(edificio_id));
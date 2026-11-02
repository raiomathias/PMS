-- PMS v3.9.1 · Restrict notification RPC execution to authenticated users
revoke execute on function public.pms_booking_notif_list() from public,anon;
revoke execute on function public.pms_booking_notif_mark(uuid) from public,anon;
revoke execute on function public.pms_booking_notif_config(boolean,text,text) from public,anon;
revoke execute on function public.pms_booking_notif_audit_action(uuid,text) from public,anon;
grant execute on function public.pms_booking_notif_list() to authenticated;
grant execute on function public.pms_booking_notif_mark(uuid) to authenticated;
grant execute on function public.pms_booking_notif_config(boolean,text,text) to authenticated;
grant execute on function public.pms_booking_notif_audit_action(uuid,text) to authenticated;
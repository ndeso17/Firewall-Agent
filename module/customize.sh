##########################################################################################
#
# Magisk / KernelSU module installer script
#
##########################################################################################

SKIPMOUNT=false
PROPFILE=false
POSTFSDATA=true
LATESTARTSERVICE=true

print_modname() {
  ui_print "*******************************"
  ui_print " AI Adaptive Firewall Module  "
  ui_print "*******************************"
}

on_install() {
  ui_print "- Extracting module files"
  unzip -o "$ZIPFILE" -x 'META-INF/*' -d "$MODPATH" >&2
}

set_permissions() {
  set_perm_recursive "$MODPATH" 0 0 0755 0644
  set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
  set_perm "$MODPATH/service.sh" 0 0 0755
  set_perm "$MODPATH/uninstall.sh" 0 0 0755
  set_perm "$MODPATH/bin/edge_runner.sh" 0 0 0755
  set_perm "$MODPATH/bin/infer_runner.sh" 0 0 0755
  set_perm "$MODPATH/bin/python_infer.py" 0 0 0755
  set_perm "$MODPATH/bin/notifier.sh" 0 0 0755
  set_perm "$MODPATH/bin/manual_action.sh" 0 0 0755
  set_perm "$MODPATH/bin/selftest_onnx.sh" 0 0 0755
  set_perm "$MODPATH/bin/collect_traffic.sh" 0 0 0755
  set_perm "$MODPATH/bin/feature_mapper.sh" 0 0 0755
  set_perm "$MODPATH/bin/publish_web_data.sh" 0 0 0755
  set_perm "$MODPATH/bin/publish_apps.sh" 0 0 0755
  set_perm "$MODPATH/bin/notify_status.sh" 0 0 0755
  set_perm "$MODPATH/bin/model_updater.sh" 0 0 0755
  set_perm "$MODPATH/bin/module_ctl.sh" 0 0 0755
  set_perm "$MODPATH/bin/ims_ril_probe.sh" 0 0 0755
  set_perm "$MODPATH/bin/ims_ril_adapter.sh" 0 0 0755
  set_perm "$MODPATH/bin/telephony_priv_setup.sh" 0 0 0755
  if [ -f "$MODPATH/bin/native/infer_runner_native" ]; then
    set_perm "$MODPATH/bin/native/infer_runner_native" 0 0 0755
  fi
  if [ -d "$MODPATH/bin/native/lib" ]; then
    set_perm_recursive "$MODPATH/bin/native/lib" 0 0 0755 0644
  fi
  set_perm "$MODPATH/webroot/api/status.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/set_mode.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/view_log.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/rules.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/incidents.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/action.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/export_prompt.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/alerts_feed.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/onnx_health.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/get_preferences.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/set_preferences.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/get_model_update.sh" 0 0 0755
  set_perm "$MODPATH/webroot/api/set_model_update.sh" 0 0 0755
}

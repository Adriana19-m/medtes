from django.urls import path
from django.contrib.auth import views as auth_views
from Aplicaciones.Medessentia import views
from django.urls import path, include
from .decorators import solo_admin, solo_doctor, solo_paciente, solo_admin_o_doctor


urlpatterns = [
    
    path("", views.home_publico, name="home_publico"),
    path('redirigir/', views.redirigir_segun_rol, name='redirigir_segun_rol'),
    path('api/chatbot/', views.chatbot_api, name='chatbot_api'),
    path('chatbot/agendar/', views.chatbot_redirigir_agendamiento, name='chatbot_agendar'),
    path('chatbot/info-citas/', views.chatbot_info_agendamiento, name='chatbot_info_citas'),
   
    path("panel_admin/", views.panel_admin, name="panel_admin"),
    path("panel_doctor/", views.panel_doctor, name="panel_doctor"),
    path("panel_paciente/", views.panel_paciente, name="panel_paciente"),
    
    path(
    "login/",
    auth_views.LoginView.as_view(
        template_name="auth/login.html",
        extra_context={"hide_register_link": True},
    ),
    name="login",
    ),

    path("logout/", auth_views.LogoutView.as_view(next_page="/"), name="logout"),
    path("redirigir/", views.redirigir_segun_rol, name="redirigir_segun_rol"),
    # -------------------------
    # Registro y perfil
    # -------------------------
    path("registro/", views.registro, name="registro"),
    path("mi-perfil/", views.mi_perfil, name="mi_perfil"),
    path("editar-perfil/", views.editar_perfil, name="editar_perfil"),

    path("pacientes/<int:perfil_id>/perfil/", views.perfil_paciente, name="perfil_paciente"),
    path("pacientes/<int:perfil_id>/historia/", views.historia_paciente, name="historia_paciente"),
    path("pacientes/<int:perfil_id>/nuevo-signo/", views.nuevo_signo, name="nuevo_signo"),
    # -------------------------
    # Roles y permisos
    # -------------------------
    path("lista-perfiles/", views.lista_perfiles, name="lista_perfiles"),
    path("admin-dashboard/", views.panel_admin, name="panel_admin"),
    path("doctor-dashboard/", views.panel_doctor, name="panel_doctor"),
    path("paciente-dashboard/", views.panel_paciente, name="panel_paciente"),
    path("asignar-roles/", views.asignar_roles, name="asignar_roles"),
    
    path("lista-usuarios/", views.lista_usuarios, name="lista_usuarios"),
    path("usuarios/<int:user_id>/toggle-activo/", views.toggle_activo, name="toggle_activo"),
    path("usuarios/exportar-csv/", views.exportar_usuarios_csv, name="exportar_usuarios_csv"),
    path("mi-cuenta/", views.editar_cuenta, name="editar_cuenta"),
    path("registro-paciente/", views.registro_paciente, name="registro_paciente"),

    path("redirigir/", views.redirigir_segun_rol, name="redirigir_segun_rol"),

    path(
        "password-change/",
        auth_views.PasswordChangeView.as_view(
            template_name="auth/password_change_form.html",
            success_url="/password-change/done/"
        ),
        name="password_change",
        ),
        path(
        "password-change/done/",
        auth_views.PasswordChangeDoneView.as_view(
            template_name="auth/password_change_done.html"
        ),
        name="password_change_done",
        ),
    
    path(
    "password-reset/",
    auth_views.PasswordResetView.as_view(
        template_name="auth/password_reset_form.html",
        email_template_name="auth/password_reset_email.txt",
        subject_template_name="auth/password_reset_subject.txt",
        success_url="/password-reset/done/"
    ),
    name="password_reset",
    ),
    path(
    "password-reset/done/",
    auth_views.PasswordResetDoneView.as_view(template_name="auth/password_reset_done.html"),
    name="password_reset_done",
    ),
    path(
    "reset/<uidb64>/<token>/",
    auth_views.PasswordResetConfirmView.as_view(
        template_name="auth/password_reset_confirm.html",
        success_url="/reset/done/"
    ),
    name="password_reset_confirm",
    ),
    path(
    "reset/done/",
    auth_views.PasswordResetCompleteView.as_view(template_name="auth/password_reset_complete.html"),
    name="password_reset_complete",
    ),

    path("signos-vitales/", views.signos_vitales, name="signos_vitales"),
    path("listado-signos-vitales/", views.listado_signos_vitales, name="listado_signos_vitales"),
    path("nuevo-signo-vital/", views.guardar_signos_vitales, name="nuevo_signo_vital"),
    path("editar-signo-vital/<int:id>/", views.editar_signo_vital, name="editar_signo_vital"),
    path("eliminar-signo-vital/<int:id>/", views.eliminar_signo_vital, name="eliminar_signo_vital"),
    path('clear-form-errors/', views.clear_form_errors, name='clear_form_errors'),
 
    # Cita
    path("cita/", views.cita_index, name="cita_index"),
    path("cita/elegir-doctor/", views.elegir_doctor, name="cita_elegir_doctor"),
    path("cita/doctor/<int:id_doctor>/agenda/", views.agenda_paciente, name="cita_agenda_paciente"),
    path("cita/doctor/<int:id_doctor>/horarios/", views.horarios_disponibles, name="cita_horarios_disponibles"),
    path("cita/doctor/<int:id_doctor>/agendar/", views.agendar_cita_ajax, name="cita_agendar_cita_ajax"),
    path("cita/<int:id_cita>/atender/", views.marcar_cita_atendida, name="marcar_cita_atendida"),
    path("cita/<int:id_cita>/eliminar/", views.eliminar_cita, name="eliminar_cita"),

    # Horario doctor
    path('horario/index/', views.horario_index, name='horario_index'),
    path('horario/', views.horario_calendario, name='horario_calendario'),
    path('horario/eventos/', views.horario_eventos, name='horario_eventos'),
    path('horario/disponibilidad/', views.horario_disponibilidad, name='horario_disponibilidad'),
    path('horario/guardar/', views.guardar_disponibilidad, name='guardar_disponibilidad'),
    path('horario/eliminar/', views.horario_eliminar, name='horario_eliminar'),
    path('horario/formulario/', views.horario_formulario, name='horario_formulario'),
    path('horario/listar/', views.horario_listar, name='horario_listar'),
    
      # CIE-10
    path('cie10', views.cie10_inicio, name='cie10_inicio'),
    path('listado/', views.cie10_listado, name='cie10_listado'),
    path('formulario/', views.cie10_formulario, name='cie10_formulario'),
    path('guardar/', views.cie10_guardar, name='cie10_guardar'),
    path('eliminar/', views.cie10_eliminar, name='cie10_eliminar'),
    # Historia Clínica
    path('inicio/', views.inicio_historiaclinica, name='inicio_historiaclinica'),
    path('ajax/listado/', views.listado_historias, name='listado_historias'),
    path('ajax/formulario/', views.obtener_formulario, name='obtener_formulario'),
    path('ajax/guardar/', views.guardar_historia, name='guardar_historia'),
    path('ajax/detalle/<int:id>/', views.detalle_historia, name='detalle_historia'),
    path('ajax/eliminar/', views.eliminar_historia, name='eliminar_historia'),
    path('ajax/buscar-pacientes/', views.buscar_pacientes, name='buscar_pacientes'),
    path('ajax/crear-paciente-rapido/', views.crear_paciente_rapido, name='crear_paciente_rapido'),
    path('ajax/generar-expediente/', views.generar_expediente, name='generar_expediente'),
    path('ajax/obtener-datos-paciente/', views.obtener_datos_paciente, name='obtener_datos_paciente'),
    # Atención Médica
    path('atencion/', views.inicio_atencion, name='inicio_atencion'),
    path('ajax/atencion/listado/', views.listado_atenciones, name='listado_atenciones'),
    path('ajax/atencion/obtener-formulario/', views.obtener_formulario_atencion, name='obtener_formulario_atencion'),
    path('ajax/atencion/guardar/', views.guardar_atencion, name='guardar_atencion'),
    path('ajax/atencion/detalle/<int:id>/', views.detalle_atencion, name='detalle_atencion'),
    path('ajax/atencion/eliminar/', views.eliminar_atencion, name='eliminar_atencion'),
    path('ajax/atencion/buscar-historias/', views.buscar_historias_atencion, name='buscar_historias_atencion'),
    path('ajax/atencion/buscar-cie10/', views.buscar_cie10_atencion, name='buscar_cie10_atencion'),
    path('atencion/obtener-ultimos-signos/', views.obtener_ultimos_signos, name='obtener_ultimos_signos'),

      # Vista principal
    path('recetas/', views.inicio_receta, name='inicio_receta'),
    # Historias clínicas
    path('historias/listar/', views.obtener_historias, name='historias_listar'),
    path('historias/listar/', views.obtener_historias, name='historias_listar'),
    path('recetas/listar/', views.listado_recetas, name='recetas_listar'),
    path('recetas/formulario/', views.obtener_formulario_receta, name='recetas_formulario'),
    path('recetas/guardar/', views.guardar_receta, name='recetas_guardar'),
    path('recetas/<int:id>/detalle/', views.detalle_receta, name='recetas_detalle'),
    path('recetas/anular/', views.anular_receta, name='recetas_anular'),
    path('recetas/eliminar/', views.eliminar_receta, name='recetas_eliminar'),
    # Vistas principales
    #certificados médicos
    path('certificados/', views.inicio_certificado, name='inicio_certificado'),
    path('certificados/listado/', views.certificado_listado, name='certificado_listado'),
    path('certificados/formulario/', views.certificado_formulario, name='certificado_formulario'),
    path('certificados/guardar/', views.certificado_guardar, name='certificado_guardar'),
    path('certificados/eliminar/', views.certificado_eliminar, name='certificado_eliminar'),
    path('certificados/imprimir/<int:id>/', views.imprimir_certificado, name='imprimir_certificado'),
    path('certificados/reactivar/', views.certificado_reactivar, name='certificado_reactivar'),
    # Agrega estas URLs después de tus URLs existentes:
    path('reportes/', views.reportes_dashboard, name='reportes_dashboard'),
    path('reportes/citas-data/', views.reportes_citas_ajax, name='reportes_citas_ajax'),
]

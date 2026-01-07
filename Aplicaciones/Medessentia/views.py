import traceback
import pytz
import requests
import json
import re

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.contrib import messages
from .models import PerfilUsuario, SignosVitales
from decimal import Decimal
from django.http import JsonResponse
from datetime import date, time, datetime
from django.utils.dateparse import parse_datetime
from django.db import IntegrityError, transaction
from django.db.models import Prefetch
from django.views.decorators.http import require_http_methods
from django.db import transaction, connection
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.views.decorators.http import require_POST
from django.core.exceptions import MultipleObjectsReturned
from datetime import timedelta
from django.utils import timezone
from django.core.exceptions import PermissionDenied
from django.db.models import Max, Q, Case, When, Value, IntegerField
from decimal import Decimal, InvalidOperation
from django.http import HttpResponseRedirect,JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from Aplicaciones.Medessentia.models import HorarioDoctor, Cita
from django.conf import settings
# receta_medica/views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone
from django.contrib.auth.models import User
import json
from .models import Receta, RecetaDetalle, HistoriaClinica, AtencionMedica
from django.http import JsonResponse, HttpResponse
from django.db import transaction
from django.conf import settings
from datetime import datetime, date, timedelta
import os
from Aplicaciones.Medessentia.models import AtencionMedica
from .models import CertificadoMedico
from datetime import datetime
from .models import AtencionMedica, HistoriaClinica, Cie10, User, PerfilUsuario
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.contrib.auth.decorators import login_required
from django.middleware.csrf import get_token
from .models import Cie10
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.db.models import Q, Count
from datetime import datetime, date, timedelta
from .models import Cita, HorarioDoctor, User, PerfilUsuario  
from django.http import HttpResponseRedirect
from datetime import datetime
from django.db.models.functions import TruncDay
from django.urls import reverse


from django.contrib.auth.models import User, Group
from django.db import transaction
from django.template.loader import render_to_string
from datetime import datetime, date
from .models import HistoriaClinica, PerfilUsuario
from django.shortcuts import render
print(datetime.now())

def home_publico(request):
    """Página pública principal (tipo Medilab)."""
    es_admin = request.user.groups.filter(name="ADMINISTRADOR").exists() if request.user.is_authenticated else False
    es_doctor = request.user.groups.filter(name="DOCTOR").exists() if request.user.is_authenticated else False
    es_paciente = request.user.groups.filter(name="PACIENTE").exists() if request.user.is_authenticated else False

    context = {
        "es_admin": es_admin,
        "es_doctor": es_doctor,
        "es_paciente": es_paciente,
    }
    return render(request, "public/home_publico.html", context)


# ---------------------------------
# Helper: verificación de Administrador
# ---------------------------------
def es_admin(user):
    return user.is_superuser or user.groups.filter(name="ADMINISTRADOR").exists()

# ---------------------------------
# Utilidad: garantizar perfil
# ---------------------------------
def ensure_perfil(user):
    """
    Devuelve un (único) PerfilUsuario para el user.
    - Si no existe, lo crea con placeholders válidos.
    - Si hay duplicados, conserva uno, fusiona datos básicos y elimina el resto.
    """
    try:
        return user.perfil  # si el campo es OneToOne y no hay duplicados
    except PerfilUsuario.DoesNotExist:
        with transaction.atomic():
            return PerfilUsuario.objects.create(
                user=user,
                genero_usuario=None,
                cedula_usuario="0000000000",
                telefono_usuario="0000000000",
                direccion_usuario="",
            )
    except (MultipleObjectsReturned, PerfilUsuario.MultipleObjectsReturned):
        # Hay más de un perfil para este user
        with transaction.atomic():
            perfiles = list(PerfilUsuario.objects.filter(user=user).order_by('id'))
            keeper = perfiles[0]
            extras = perfiles[1:]

            # Fusión simple de datos (si el keeper tiene placeholders)
            for dup in extras:
                if (not keeper.direccion_usuario) and dup.direccion_usuario:
                    keeper.direccion_usuario = dup.direccion_usuario
                if (not keeper.genero_usuario) and dup.genero_usuario:
                    keeper.genero_usuario = dup.genero_usuario
                if keeper.cedula_usuario in (None, "", "0000000000") and dup.cedula_usuario not in (None, "", "0000000000"):
                    keeper.cedula_usuario = dup.cedula_usuario
                if keeper.telefono_usuario in (None, "", "0000000000") and dup.telefono_usuario not in (None, "", "0000000000"):
                    keeper.telefono_usuario = dup.telefono_usuario
            keeper.save(update_fields=["direccion_usuario","genero_usuario","cedula_usuario","telefono_usuario"])

            # Borra los duplicados
            PerfilUsuario.objects.filter(id__in=[d.id for d in extras]).delete()
            return keeper
# -------------------------
# PERFIL DE USUARIO
# -------------------------
@login_required
def mi_perfil(request):
    perfil = ensure_perfil(request.user)
    return render(request, "public/mi_perfil.html", {"perfil": perfil})
@login_required
def editar_perfil(request):
    perfil = ensure_perfil(request.user)

    if request.method == "POST":
        ced = (request.POST.get("cedula_usuario") or "").strip()
        tel = (request.POST.get("telefono_usuario") or "").strip()

        if not (ced.isdigit() and len(ced) == 10):
            messages.error(request, "La cédula debe tener 10 dígitos (sin guiones).")
            return redirect("editar_perfil")

        # Permite dejarlo vacío, pero guardamos 0000000000 para cumplir NOT NULL
        if tel and not (tel.isdigit() and len(tel) == 10):
            messages.error(request, "El teléfono debe tener 10 dígitos.")
            return redirect("editar_perfil")
        if not tel:
            tel = "0000000000"

        perfil.genero_usuario   = (request.POST.get("genero_usuario") or "").strip() or None
        perfil.cedula_usuario   = ced
        perfil.telefono_usuario = tel                        
        perfil.direccion_usuario = (request.POST.get("direccion_usuario") or "").strip()
        perfil.save()

        messages.success(request, "Perfil actualizado correctamente.")
        return redirect("mi_perfil")

    return render(request, "public/editar_perfil.html", {"perfil": perfil})


# -------------------------
# REGISTRO DE USUARIO (solo Admin)
def _sanear_telefono(valor):
    """
    Devuelve SIEMPRE 10 dígitos.
    - Si viene vacío o None -> '0000000000'
    - Si trae menos/más dígitos -> recorta/ajusta a 10
    """
    dig = "".join(ch for ch in str(valor or "") if ch.isdigit())
    if not dig:
        dig = "0000000000"
    if len(dig) < 10:
        dig = (dig + "0000000000")[:10]
    else:
        dig = dig[:10]
    return dig
# -------------------------
@user_passes_test(es_admin)
def registro(request):
    if request.method == "POST":
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password   = (request.POST.get("password") or "")
        cedula     = (request.POST.get("cedula_usuario") or "").strip()

        # Teléfono: jamás NULL
        telefono_final = _sanear_telefono(request.POST.get("telefono_usuario"))

        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = (request.POST.get("genero_usuario") or "").strip() or None
        auto_paciente = request.POST.get("asignar_paciente") == "on"

        # Validaciones mínimas
        errores = []
        if not username:
            errores.append("Debes ingresar un nombre de usuario.")
        if not email:
            errores.append("Debes ingresar un correo.")
        if not password or len(password) < 8:
            errores.append("La contraseña debe tener al menos 8 caracteres.")
        if not (cedula.isdigit() and len(cedula) == 10):
            errores.append("La cédula debe tener 10 dígitos.")
        # Si el admin escribió algo en el campo, valida 10 dígitos
        if request.POST.get("telefono_usuario"):
            if len("".join(ch for ch in request.POST.get("telefono_usuario") if ch.isdigit())) != 10:
                errores.append("El teléfono debe tener 10 dígitos.")

        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "admingen/registro.html", {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": request.POST.get("telefono_usuario", ""),
                    "direccion_usuario": direccion,
                    "genero_usuario": (genero or ""),
                    "asignar_paciente": auto_paciente,
                }
            })

        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            PerfilUsuario.objects.create(
                user=user,
                genero_usuario=genero,
                cedula_usuario=cedula,
                telefono_usuario=telefono_final,  
                direccion_usuario=direccion,
            )
            if auto_paciente:
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

        messages.success(request, f"Usuario {username} creado correctamente.")
        return redirect("lista_usuarios")

    return render(request, "admingen/registro.html")

@login_required
def editar_cuenta(request):
    user = request.user

    if request.method == "POST":
        user.first_name = request.POST.get("first_name", "").strip()
        user.last_name  = request.POST.get("last_name", "").strip()
        user.email      = request.POST.get("email", "").strip()
        user.save()
        messages.success(request, "Datos de cuenta actualizados.")
        return redirect("editar_cuenta")

    if user.groups.filter(name="ADMINISTRADOR").exists():
        template = "cuenta/editar_admin.html"
    elif user.groups.filter(name="DOCTOR").exists():
        template = "cuenta/editar_doctor.html"
    else:
        template = "cuenta/editar_paciente.html"

    return render(request, template, {"user": user})

#-----
@login_required
@user_passes_test(es_admin)
def lista_usuarios(request):
    """
    Admin: lista con filtros (rol, activo), búsqueda, orden y paginación.
    Incluye KPIs por rol y estado.
    """
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()  
    q = request.GET.get("q", "").strip()
    order = request.GET.get("order", "date_joined_desc")  

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")

    if rol:
        qs = qs.filter(groups__name=rol)

    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)

    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        )

    order_map = {
        "username_asc": "username",
        "username_desc": "-username",
        "date_joined_asc": "date_joined",
        "date_joined_desc": "-date_joined",
        "last_login_asc": "last_login",
        "last_login_desc": "-last_login",
    }
    qs = qs.order_by(order_map.get(order, "-date_joined")).distinct()

   
    kpis = {
        "total": User.objects.count(),
        "activos": User.objects.filter(is_active=True).count(),
        "inactivos": User.objects.filter(is_active=False).count(),
        "por_rol": dict(
            User.objects.values("groups__name")
            .annotate(n=Count("id"))
            .values_list("groups__name", "n")
        ),
    }

    paginator = Paginator(qs, 12)  
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "admingen/lista_usuarios.html", {
        "usuarios": page_obj.object_list,
        "page_obj": page_obj,
        "rol": rol,
        "estado": estado,
        "q": q,
        "order": order,
        "kpis": kpis,
    })

@require_POST
@login_required
@user_passes_test(es_admin)
def toggle_activo(request, user_id):
    if int(user_id) == request.user.id:
        messages.error(request, "No puedes desactivarte a ti mismo.")
        return redirect("lista_usuarios")

    u = get_object_or_404(User, id=user_id)
    u.is_active = not u.is_active
    u.save(update_fields=["is_active"])
    estado = "activado" if u.is_active else "desactivado"
    messages.success(request, f"Usuario '{u.username}' {estado}.")
    return redirect(request.META.get("HTTP_REFERER", "lista_usuarios"))

@login_required
@user_passes_test(es_admin)
def exportar_usuarios_csv(request):
    import csv
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="usuarios.csv"'
    writer = csv.writer(response)

    # Reutiliza filtros básicos
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()
    q = request.GET.get("q", "").strip()

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")
    if rol:
        qs = qs.filter(groups__name=rol)
    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)
    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        ).distinct()

    writer.writerow([
        "username","first_name","last_name","email","roles",
        "is_active","last_login","date_joined",
        "genero","cedula","telefono","direccion","fecha_registro_perfil",
    ])

    for u in qs:
        roles = ", ".join(g.name for g in u.groups.all()) or "—"
        p = getattr(u, "perfil", None)
        writer.writerow([
            u.username, u.first_name, u.last_name, u.email, roles,
            "activo" if u.is_active else "inactivo",
            u.last_login or "", u.date_joined or "",
            getattr(p, "genero_usuario", "") or "—",
            getattr(p, "cedula_usuario", "") or "—",
            getattr(p, "telefono_usuario", "") or "—",
            getattr(p, "direccion_usuario", "") or "—",
            getattr(p, "fecha_registro_usuario", "") or "",
        ])
    return response

# -------------------------
# VISTAS CON ROLES/PERMISOS
# -------------------------
@login_required
@permission_required("Medessentia.view_perfilusuario", raise_exception=True)
def lista_perfiles(request):
    perfiles = PerfilUsuario.objects.all()
    return render(request, "lista_perfiles.html", {"perfiles": perfiles})


@login_required
@user_passes_test(es_admin)
def panel_admin(request):
    
    return render(request, "dashboards/panel_admin.html")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def panel_doctor(request):
    """ Panel exclusivo para los doctores """
    signos = SignosVitales.objects.all()
    return render(request, "dashboards/panel_doctor.html")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Paciente").exists())
def panel_paciente(request):
    perfil = ensure_perfil(request.user)

    if perfil.cedula_usuario == "0000000000" or perfil.telefono_usuario == "0000000000":
        messages.warning(request, "Completa tu perfil antes de continuar.")
        return redirect("editar_perfil")

    signos = perfil.signos_vitales.all()
    return render(request, "public/panel_paciente.html", {"perfil": perfil, "signos": signos})

@require_http_methods(["GET", "POST"])
def registro_paciente(request):
   
    if request.user.is_authenticated:
        messages.info(request, "Ya has iniciado sesión.")
        return redirect("redirigir_segun_rol")

    if request.method == "POST":
        
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password1  = request.POST.get("password1") or ""
        password2  = request.POST.get("password2") or ""
        cedula     = (request.POST.get("cedula_usuario") or "").strip()
        telefono   = (request.POST.get("telefono_usuario") or "").strip()
        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = request.POST.get("genero_usuario") or None

        errores = []
        if not username:
            errores.append("El usuario es obligatorio.")
        if not email:
            errores.append("El correo es obligatorio.")
        if password1 != password2:
            errores.append("Las contraseñas no coinciden.")
        if len(cedula) != 10 or not cedula.isdigit():
            errores.append("La cédula debe tener 10 dígitos numéricos.")
        if telefono and (len(telefono) != 10 or not telefono.isdigit()):
            errores.append("El teléfono debe tener 10 dígitos numéricos.")

        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            
            context = {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": telefono,
                    "direccion_usuario": direccion,
                    "genero_usuario": genero or "",
                }
            }
            return render(request, "auth/registro_paciente.html", context)

      
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1,
                    first_name=first_name,
                    last_name=last_name,
                )
              
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

                PerfilUsuario.objects.create(
                    user=user,
                    genero_usuario=genero,
                    cedula_usuario=cedula,        
                    telefono_usuario=_sanear_telefono(telefono), 
                    direccion_usuario=direccion or "",
                )
        except Exception as e:
            messages.error(request, f"Ocurrió un error creando la cuenta: {e}")
            return render(request, "auth/registro_paciente.html", {"prefill": request.POST})

       
        login(request, user)
        messages.success(request, "¡Cuenta creada correctamente! Bienvenido/a.")
        return redirect("redirigir_segun_rol")

   
    return render(request, "auth/registro_paciente.html")
# -------------------------
# REDIRECCIÓN SEGÚN ROL
# -------------------------


@login_required
def cerrar_sesion(request):
    logout(request)
    return redirect("/")


@login_required
def redirigir_segun_rol(request):
    user = request.user

    if user.is_superuser or user.groups.filter(name="Administrador").exists():
        return HttpResponseRedirect("/panel_admin/")

    elif user.groups.filter(name="Doctor").exists():
        return HttpResponseRedirect("/panel_doctor/")

    elif user.groups.filter(name="Paciente").exists():
        return HttpResponseRedirect("/panel_paciente/")

    else:
        messages.error(request, "No tienes un rol asignado. Contacta con el administrador.")
        return HttpResponseRedirect("/mi_perfil/")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    hoy = timezone.now()
    qs = (PerfilUsuario.objects
          .filter(user__groups__name="Paciente")
          .select_related("user")
          .annotate(
              ultimo_control=Max("signos_vitales__fecha_registro")
          ))

    
    treinta = hoy - timedelta(days=30)
    sesenta = hoy - timedelta(days=60)
    qs = qs.annotate(
        estado_control=Case(
            When(ultimo_control__isnull=True, then=Value(0)),
            When(ultimo_control__gte=treinta, then=Value(1)),
            When(ultimo_control__lt=treinta, ultimo_control__gte=sesenta, then=Value(2)),
            default=Value(3),
            output_field=IntegerField()
        )
    )

    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(user__first_name__icontains=q) |
            Q(user__last_name__icontains=q) |
            Q(user__username__icontains=q) |
            Q(cedulaUsuario__icontains=q) |
            Q(telefono_usuario__icontains=q)
        )


    order = request.GET.get("order") or "-ultimo_control"
    qs = qs.order_by(order, "user__username")

    total = qs.count()
    con_datos = qs.filter(ultimo_control__isnull=False)
    kpis = {
        "total": total,
        "ok": con_datos.filter(ultimo_control__gte=treinta).count(),
        "pronto": con_datos.filter(ultimo_control__lt=treinta, ultimo_control__gte=sesenta).count(),
        "vencido": con_datos.filter(ultimo_control__lt=sesenta).count(),
        "sindatos": qs.filter(ultimo_control__isnull=True).count(),
    }

    paginator = Paginator(qs, 12)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "doctor/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })
# ----------- PARA PACIENTES 
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    ...
    return render(request, "pacientes/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })

@login_required
def historia_paciente(request, perfil_id):
    """Detalle simple de historia: lista de signos vitales del paciente."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    signos = perfil.signos_vitales.all().order_by("-fecha_registro")
    return render(request, "doctor/historia_paciente.html", {
        "perfil": perfil,
        "signos": signos,
    })


@login_required
def perfil_paciente(request, perfil_id):
    """Ficha rápida del paciente (datos del perfil)."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    return render(request, "doctor/perfil_paciente.html", {
        "perfil": perfil,
    })
# -------------------------
# ASIGNAR ROLES (rol único)
# -------------------------
@login_required
@user_passes_test(es_admin)
def asignar_roles(request):
    usuarios = User.objects.all().order_by("username")
    grupos = Group.objects.all().order_by("name")

    if request.method == "POST":
        usuario_id = request.POST.get("usuario_id")
        rol = request.POST.get("rol")
        if usuario_id and rol:
            usuario = get_object_or_404(User, id=usuario_id)
            grupo = get_object_or_404(Group, name=rol)
            usuario.groups.clear()
            usuario.groups.add(grupo)
            messages.success(request, f"Rol '{rol}' asignado a {usuario.username}")
            return redirect("asignar_roles")

 
    return render(request, "admingen/asignar_roles.html", {"usuarios": usuarios, "grupos": grupos})

@login_required
def lista_perfiles(request):
    qs = PerfilUsuario.objects.select_related("user")

    if request.user.groups.filter(name="Doctor").exists():
        qs = qs.filter(user__groups__name="Paciente")
        solo_pacientes = True

    elif request.user.groups.filter(name="Paciente").exists():
        qs = qs.filter(user=request.user)
        solo_pacientes = False

    else:
        solo_pacientes = False

    perfiles = qs.distinct().order_by("user__username")

    return render(request, "lista_perfiles.html", {
        "perfiles": perfiles,
        "solo_pacientes": solo_pacientes,
    })

# -------------------------
# SIGNOS VITALES
# -------------------------
def es_doctor_o_admin(u):
    return u.is_authenticated and (u.groups.filter(name="Doctor").exists() or es_admin(u))

@login_required
@user_passes_test(es_doctor_o_admin)
def nuevo_signo(request, perfil_id):
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)

    if request.method == "POST":
       
        fecha_raw = (request.POST.get("fecha_registro") or "").strip()

       
        pas_raw = (request.POST.get("pa_sistolica") or "").strip()
        pad_raw = (request.POST.get("pa_diastolica") or "").strip()
        pam_raw = (request.POST.get("pa_media") or "").strip()

       
        temp_raw = (request.POST.get("temperatura") or "").strip()
        fr_raw   = (request.POST.get("frecuencia_respiratoria") or "").strip()
        fc_raw   = (request.POST.get("frecuencia_cardiaca") or "").strip()
        spo2_raw = (request.POST.get("saturacion_oxigeno") or "").strip()

      
        peso_raw  = (request.POST.get("peso") or "").strip()
        talla_raw = (request.POST.get("talla") or "").strip()
        imc_raw   = (request.POST.get("imc") or "").strip()

      
        glucosa_raw    = (request.POST.get("glucosa_capilar") or "").strip()
        hemoglobina_raw = (request.POST.get("hemoglobina") or "").strip()

        obs = (request.POST.get("observaciones") or "").strip()

        errores = []

       
        fecha_registro = parse_datetime(fecha_raw) if fecha_raw else timezone.now()
        if fecha_raw and not fecha_registro:
            errores.append("Fecha inválida. Usa el formato YYYY-MM-DD HH:MM.")

        
        def to_int(name, raw, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                return int(raw)
            except ValueError:
                errores.append(f"{name} debe ser un número entero.")
                return None

   
        def to_dec(name, raw, ndigits=None, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                d = Decimal(raw)
                return d if ndigits is None else d.quantize(Decimal(ndigits))
            except (InvalidOperation, ValueError):
                errores.append(f"{name} debe ser un número válido.")
                return None

   
        pas = to_int("Presión sistólica (PAS)", pas_raw, obligatorio=False)
        pad = to_int("Presión diastólica (PAD)", pad_raw, obligatorio=False)
        pam = to_dec("Presión arterial media (PAM)", pam_raw, "0.01", obligatorio=False)

        fc  = to_int("Frecuencia cardiaca", fc_raw, obligatorio=True)
        fr  = to_int("Frecuencia respiratoria", fr_raw, obligatorio=True)
        spo2 = to_int("Saturación de oxígeno", spo2_raw, obligatorio=True)
        temp = to_dec("Temperatura", temp_raw, "0.1", obligatorio=True)

        
        peso  = to_dec("Peso",  peso_raw,  "0.01", obligatorio=True)
        talla = to_dec("Talla", talla_raw, "0.01", obligatorio=True)
        imc   = to_dec("IMC",   imc_raw,   "0.01", obligatorio=False)

        glucosa     = to_dec("Glucosa capilar", glucosa_raw, "0.1", obligatorio=False)
        hemoglobina = to_dec("Hemoglobina",     hemoglobina_raw, "0.1", obligatorio=False)

        
        if temp is not None and not (Decimal("30.0") <= temp <= Decimal("45.0")):
            errores.append("Temperatura fuera de rango razonable (30.0 – 45.0 °C).")
        if spo2 is not None and not (50 <= spo2 <= 100):
            errores.append("SpO₂ debe estar entre 50 y 100.")
        if peso is not None and peso <= 0:
            errores.append("El peso debe ser > 0.")
        if talla is not None and talla <= 0:
            errores.append("La talla debe ser > 0.")

    
        if pam is None and (pas is not None and pad is not None):
            pam = (Decimal(2) * Decimal(pad) + Decimal(pas)) / Decimal(3)
            pam = pam.quantize(Decimal("0.01"))

        
        if imc is None and (peso is not None and talla is not None and talla > 0):
            imc = (peso / (talla * talla)).quantize(Decimal("0.01"))

       
        presion_compuesta = ""
        if pas is not None and pad is not None:
            presion_compuesta = f"{pas}/{pad}"
        else:
            presion_compuesta = "No registrada" 

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "doctor/nuevo_signo.html", {
                "perfil": perfil,
                "prefill": {
                    "fecha_registro": fecha_raw,
                    "pa_sistolica": pas_raw,
                    "pa_diastolica": pad_raw,
                    "pa_media": pam_raw or (str(pam) if pam is not None else ""),
                    "temperatura": temp_raw,
                    "frecuencia_respiratoria": fr_raw,
                    "frecuencia_cardiaca": fc_raw,
                    "saturacion_oxigeno": spo2_raw,
                    "peso": peso_raw,
                    "talla": talla_raw,
                    "imc": imc_raw or (str(imc) if imc is not None else ""),
                    "glucosa_capilar": glucosa_raw,
                    "hemoglobina": hemoglobina_raw,
                    "observaciones": obs,
                },
            })

      
        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,   
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=obs,
            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hemoglobina,
        )

        messages.success(request, "Signos vitales añadidos correctamente.")
        return redirect("historia_paciente", perfil_id=perfil.id)

    return render(request, "doctor/nuevo_signo.html", {
        "perfil": perfil,
        "prefill": {
            "fecha_registro": timezone.now().strftime("%Y-%m-%d %H:%M"),
        },
    })
@login_required
def signos_vitales(request):
    """Listado general de signos vitales.
       - Doctor: ve todos
       - Paciente: ve solo los suyos
    """
    if request.user.groups.filter(name="Doctor").exists() or request.user.is_superuser:
        signos = (SignosVitales.objects
                  .select_related("perfil_usuario", "perfil_usuario__user")
                  .order_by("-fecha_registro"))
    else:
        perfil = ensure_perfil(request.user)
        signos = (perfil.signos_vitales
                  .select_related("perfil_usuario__user")
                  .order_by("-fecha_registro"))
    return render(request, "vistasignos/signos_vitales.html", {"signos": signos})


@login_required
def listado_signos_vitales(request):
    """Alias si quieres otra ruta/lista; puedes eliminarla si no la usas."""
    return signos_vitales(request)


@login_required
def guardar_signos_vitales(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Solo se permite POST."})

    perfil = ensure_perfil(request.user)
    try:
        fecha_registro = parse_datetime(request.POST.get("fecha_registro")) or timezone.now()
        fc  = int(request.POST.get("frecuencia_cardiaca", 0))
        fr  = int(request.POST.get("frecuencia_respiratoria", 0))
        temp = Decimal(request.POST.get("temperatura", "0.0"))
        spo2 = int(request.POST.get("saturacion_oxigeno", 0))
        peso = Decimal(request.POST.get("peso", "0.0"))
        talla = Decimal(request.POST.get("talla", "0.0"))
        imc_raw = request.POST.get("imc")
        imc = Decimal(imc_raw) if imc_raw else None

        pas_raw = request.POST.get("pa_sistolica") or ""
        pad_raw = request.POST.get("pa_diastolica") or ""
        pam_raw = request.POST.get("pa_media") or ""
        gluc_raw = request.POST.get("glucosa_capilar") or ""
        hb_raw   = request.POST.get("hemoglobina") or ""

        pas = int(pas_raw) if pas_raw else None
        pad = int(pad_raw) if pad_raw else None
        pam = Decimal(pam_raw) if pam_raw else None
        glucosa = Decimal(gluc_raw) if gluc_raw else None
        hb = Decimal(hb_raw) if hb_raw else None

        presion_compuesta = f"{pas}/{pad}" if (pas is not None and pad is not None) else ""

        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=request.POST.get("observaciones",""),

            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hb,
        )
        return JsonResponse({"success": True, "message": "Signos vitales guardados correctamente."})
    except Exception as e:
        return JsonResponse({"success": False, "message": f"Error: {e}"})
@login_required
def editar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id
    
    # Verificar permisos
    if not (request.user.groups.filter(name="Doctor").exists() or request.user.is_superuser):
        messages.error(request, "No tienes permiso para editar signos vitales.")
        return redirect('historia_paciente', perfil_id=perfil_id)
    
    if request.method == "POST":
        try:
            # Obtener valores del formulario
            fecha_raw = request.POST.get("fecha_registro", "").strip()
            pas_raw = request.POST.get("pa_sistolica", "").strip()
            pad_raw = request.POST.get("pa_diastolica", "").strip()
            pam_raw = request.POST.get("pa_media", "").strip()
            temp_raw = request.POST.get("temperatura", "").strip()
            fr_raw = request.POST.get("frecuencia_respiratoria", "").strip()
            fc_raw = request.POST.get("frecuencia_cardiaca", "").strip()
            spo2_raw = request.POST.get("saturacion_oxigeno", "").strip()
            peso_raw = request.POST.get("peso", "").strip()
            talla_raw = request.POST.get("talla", "").strip()
            imc_raw = request.POST.get("imc", "").strip()
            glucosa_raw = request.POST.get("glucosa_capilar", "").strip()
            hemoglobina_raw = request.POST.get("hemoglobina", "").strip()
            obs = request.POST.get("observaciones", "").strip()
            
            # Validaciones básicas
            errores = []
            
            # Fecha
            fecha_registro = parse_datetime(fecha_raw) if fecha_raw else signo.fecha_registro
            
            # Convertir y validar valores
            def parse_int(valor, nombre, obligatorio=True):
                if not valor and not obligatorio:
                    return None
                try:
                    return int(valor)
                except (ValueError, TypeError):
                    errores.append(f"{nombre} debe ser un número entero válido.")
                    return None
            
            def parse_decimal(valor, nombre, obligatorio=True):
                if not valor and not obligatorio:
                    return None
                try:
                   
                    valor = valor.replace(',', '.')
                    return Decimal(valor)
                except (ValueError, InvalidOperation, TypeError):
                    errores.append(f"{nombre} debe ser un número válido.")
                    return None

            
            # Campos obligatorios
            fc = parse_int(fc_raw, "Frecuencia cardiaca", obligatorio=True)
            fr = parse_int(fr_raw, "Frecuencia respiratoria", obligatorio=True)
            spo2 = parse_int(spo2_raw, "Saturación de oxígeno", obligatorio=True)
            temp = parse_decimal(temp_raw, "Temperatura", obligatorio=True)
            peso = parse_decimal(peso_raw, "Peso", obligatorio=True)
            talla = parse_decimal(talla_raw, "Talla", obligatorio=True)
            
            # Campos opcionales
            pas = parse_int(pas_raw, "Presión sistólica", obligatorio=False)
            pad = parse_int(pad_raw, "Presión diastólica", obligatorio=False)
            pam = parse_decimal(pam_raw, "Presión arterial media", obligatorio=False)
            imc = parse_decimal(imc_raw, "IMC", obligatorio=False)
            glucosa = parse_decimal(glucosa_raw, "Glucosa capilar", obligatorio=False)
            hemoglobina = parse_decimal(hemoglobina_raw, "Hemoglobina", obligatorio=False)
            
            # Validaciones de rango
            if temp is not None and (temp < Decimal('30.0') or temp > Decimal('45.0')):
                errores.append("Temperatura debe estar entre 30.0 y 45.0 °C.")
            
            if spo2 is not None and (spo2 < 50 or spo2 > 100):
                errores.append("Saturación de oxígeno debe estar entre 50 y 100%.")
            
            if peso is not None and peso <= 0:
                errores.append("El peso debe ser mayor a 0.")
            
            if talla is not None and talla <= 0:
                errores.append("La talla debe ser mayor a 0.")
            
            # Si hay errores, mostrarlos
            if errores:
                for error in errores:
                    messages.error(request, error)
                
                # Guardar los valores ingresados para rellenar el formulario
                context = {
                    'signo': signo,
                    'prefill': {
                        'fecha_registro': fecha_raw,
                        'pa_sistolica': pas_raw,
                        'pa_diastolica': pad_raw,
                        'pa_media': pam_raw,
                        'temperatura': temp_raw,
                        'frecuencia_respiratoria': fr_raw,
                        'frecuencia_cardiaca': fc_raw,
                        'saturacion_oxigeno': spo2_raw,
                        'peso': peso_raw,
                        'talla': talla_raw,
                        'imc': imc_raw,
                        'glucosa_capilar': glucosa_raw,
                        'hemoglobina': hemoglobina_raw,
                        'observaciones': obs,
                    }
                }
                return render(request, "signos_vitales/editar.html", context)
            
            # Calcular PAM si no se proporcionó
            if pam is None and pas is not None and pad is not None:
                pam = (Decimal(2) * Decimal(pad) + Decimal(pas)) / Decimal(3)
                pam = pam.quantize(Decimal('0.01'))
            
            # Calcular IMC si no se proporcionó
            if imc is None and peso is not None and talla is not None and talla > 0:
                imc = (peso / (talla * talla)).quantize(Decimal('0.01'))
            
            # Presión arterial compuesta
            presion_compuesta = ""
            if pas is not None and pad is not None:
                presion_compuesta = f"{pas}/{pad}"
            else:
                presion_compuesta = "No registrada"
            
            # Actualizar el registro
            signo.fecha_registro = fecha_registro
            signo.pa_sistolica = pas
            signo.pa_diastolica = pad
            signo.pa_media = pam
            signo.presion_arterial = presion_compuesta
            signo.frecuencia_cardiaca = fc
            signo.frecuencia_respiratoria = fr
            signo.temperatura = temp
            signo.saturacion_oxigeno = spo2
            signo.peso = peso
            signo.talla = talla
            signo.imc = imc
            signo.glucosa_capilar = glucosa
            signo.hemoglobina = hemoglobina
            signo.observaciones = obs
            
            signo.save()
            
            messages.success(request, "Signos vitales actualizados correctamente.")
            return redirect('historia_paciente', perfil_id=perfil_id)
            
        except Exception as e:
            messages.error(request, f"Error al actualizar: {str(e)}")
            return render(request, "signos_vitales/editar.html", {'signo': signo})
    
    # GET request - mostrar formulario
    return render(request, "signos_vitales/editar.html", {'signo': signo})
@login_required
def clear_form_errors(request):
    """Limpia los errores de formulario de la sesión"""
    # Limpiar todas las claves relacionadas con errores
    keys_to_remove = [
        'editar_signo_errores', 
        'editar_signo_prefill',
        'form_errors',
        'prefill_data'
    ]
    
    for key in keys_to_remove:
        if key in request.session:
            del request.session[key]
    
    return JsonResponse({'status': 'ok'})
@login_required
def eliminar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id
    signo.delete()
    messages.success(request, "Registro eliminado correctamente.")
    return redirect("historia_paciente", perfil_id=perfil_id)


def ok(data=None, message="OK", status=200):
    return JsonResponse({"ok": True, "message": message, "data": data or {}}, status=status)

def bad(message="Error de validación", data=None, status=400):
    return JsonResponse({"ok": False, "message": message, "data": data or {}}, status=status)

def require(method, request):
    if request.method != method:
        return bad(f"Solo {method}", status=405)
    return None

# ========== 4) Cita ==========
# =====================================================
# 1) PANEL DE CITAS PARA DOCTOR
# =====================================================
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def cita_index(request):
    """Muestra todas las citas asignadas al doctor logueado."""
    citas = Cita.objects.filter(id_doctor=request.user).select_related(
        'id_paciente', 'id_horario'
    ).order_by('-fecha_hora')

    return render(request, 'cita/index.html', {'citas': citas})
# =====================================================
# 2) SELECCIÓN DE DOCTOR POR PACIENTE
# =====================================================
@login_required
def elegir_doctor(request):
    doctors = User.objects.filter(groups__name='Doctor', is_active=True)
    if not doctors.exists():
        return HttpResponseRedirect("/sin_doctores/")
    return render(request, 'cita/elegir_doctor.html', {'doctors': doctors})


@login_required
def agenda_paciente(request, id_doctor):
    doctor = get_object_or_404(User, pk=id_doctor, groups__name='Doctor')
    
    # Verificar si el paciente ya tiene cita activa
    tiene_cita_activa = Cita.objects.filter(
        id_paciente=request.user,
        estado__in=["PENDIENTE", "CONFIRMADA"]
    ).exists()
    
    cita_activa = None
    if tiene_cita_activa:
        cita_activa = Cita.objects.filter(
            id_paciente=request.user,
            estado__in=["PENDIENTE", "CONFIRMADA"]
        ).first()
    
    return render(request, 'cita/agenda_paciente.html', {
        'doctor': doctor,
        'tiene_cita_activa': tiene_cita_activa,
        'cita_activa': cita_activa
    })


# =====================================================
# 4) ENDPOINT JSON — Horarios disponibles
# =====================================================
@login_required
def horarios_disponibles(request, id_doctor):
    try:
        tz_ecuador = pytz.timezone('America/Guayaquil')

        start = request.GET.get("start")
        end = request.GET.get("end")

        if not start or not end:
            return JsonResponse([], safe=False)

        start_dt = timezone.make_aware(datetime.fromisoformat(start[:19]), tz_ecuador)
        end_dt = timezone.make_aware(datetime.fromisoformat(end[:19]), tz_ecuador)

        horarios = HorarioDoctor.objects.filter(
            id_doctor=id_doctor,
            tipo_horario="TRABAJO",
            fecha_fin__gte=start_dt.date(),
            fecha_inicio__lte=end_dt.date()
        )

        events = []
        duracion_slot = timedelta(minutes=30)

        weekday_map = {
            0: 'Lunes', 1: 'Martes', 2: 'Miercoles',
            3: 'Jueves', 4: 'Viernes', 5: 'Sabado', 6: 'Domingo'
        }

        cur_date = start_dt.date()
        while cur_date <= end_dt.date():

            for h in horarios.filter(
                dia_semana=weekday_map[cur_date.weekday()],
                fecha_inicio__lte=cur_date,
                fecha_fin__gte=cur_date
            ):
                start_time = datetime.combine(cur_date, h.hora_inicio)
                end_time = datetime.combine(cur_date, h.hora_fin)

                citas_ocupadas = Cita.objects.filter(
                    id_horario=h,
                    estado__in=["PENDIENTE", "CONFIRMADA"]
                ).values_list("fecha_hora", flat=True)

                ocupados = set(
                    c.replace(tzinfo=None)
                    for c in citas_ocupadas
                )

                current = start_time
                while current + duracion_slot <= end_time:
                    slot_datetime = current.replace(tzinfo=None)

                    slot_ocupado = slot_datetime in ocupados

                    if not slot_ocupado:
                        events.append({
                            "id": str(h.id_horario),
                            "title": "Disponible",
                            "start": current.isoformat(),
                            "end": (current + duracion_slot).isoformat(),
                            "backgroundColor": "#28a745",
                            "borderColor": "#28a745",
                            "allDay": False,
                            "extendedProps": {
                                "id_horario": h.id_horario,
                                "disponible": True,
                                "hora_inicio": current.strftime("%H:%M"),
                                "hora_fin": (current + duracion_slot).strftime("%H:%M"),
                            }
                        })

                    current += duracion_slot

            cur_date += timedelta(days=1)

        return JsonResponse(events, safe=False)

    except Exception:
        traceback.print_exc()
        return JsonResponse({"error": "Error interno"}, status=500)


@login_required
@require_POST
def marcar_cita_atendida(request, id_cita):
    """Marca una cita como atendida"""
    try:
        cita = Cita.objects.get(id_cita=id_cita, id_doctor=request.user)
        if cita.estado != "ATENDIDA":
            cita.estado = "ATENDIDA"
            cita.save()
            return JsonResponse({"status": "success", "message": "Cita marcada como atendida."})
        else:
            return JsonResponse({"status": "warning", "message": "Esta cita ya estaba marcada como atendida."})
    except Cita.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Cita no encontrada."}, status=404)
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error interno: {str(e)}"}, status=500)


@login_required
@require_POST
def eliminar_cita(request, id_cita):
    """Elimina una cita del sistema"""
    try:
        cita = Cita.objects.get(id_cita=id_cita, id_doctor=request.user)
        cita.delete()
        return JsonResponse({"status": "success", "message": "Cita eliminada correctamente."})
    except Cita.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Cita no encontrada."}, status=404)
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Error interno: {str(e)}"}, status=500)
# =====================================================
# 5) ENDPOINT AJAX — Agendar cita
# =====================================================
from django.utils import timezone
from datetime import datetime, time, timedelta
import traceback
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from .models import HorarioDoctor, Cita

@login_required
@require_http_methods(["POST"])
def agendar_cita_ajax(request, id_doctor):
    user = request.user
    horario_id = request.POST.get("horario_id")
    motivo = request.POST.get("motivo", "").strip()
    hora_cita = request.POST.get("hora_cita")

    if not horario_id:
        return JsonResponse({"status": "error", "message": "No se envió id de horario"}, status=400)

    if "-" in horario_id:
        horario_id = horario_id.split("-")[0]

    try:
        horario = HorarioDoctor.objects.get(id_horario=int(horario_id), id_doctor=id_doctor)
    except HorarioDoctor.DoesNotExist:
        return JsonResponse({
            "status": "error",
            "message": f"Horario {horario_id} no encontrado para el doctor."
        }, status=404)

    try:
        # VERIFICAR SI EL PACIENTE YA TIENE UNA CITA PENDIENTE/CONFIRMADA
        citas_activas = Cita.objects.filter(
            id_paciente=user,
            estado__in=["PENDIENTE", "CONFIRMADA"]
        ).count()
        
        if citas_activas >= 1:
            return JsonResponse({
                "status": "error",
                "message": "Ya tienes una cita pendiente o confirmada. No puedes agendar otra hasta que se atienda o cancele la existente."
            }, status=409)
        
        # VERIFICAR SI EL HORARIO YA PASÓ (NUEVA VALIDACIÓN)
        h, m = map(int, hora_cita.split(":"))
        hora_inicio_obj = time(h, m)
        
        # Crear datetime combinando la fecha del horario con la hora seleccionada
        fecha_hora_cita = datetime.combine(horario.fecha_inicio, hora_inicio_obj)
        
        # Hacer la fecha/hora aware (con zona horaria) para comparar con timezone.now()
        if timezone.is_naive(fecha_hora_cita):
            fecha_hora_cita = timezone.make_aware(fecha_hora_cita, timezone.get_current_timezone())
        
        # Verificar si la cita es en el pasado
        if fecha_hora_cita < timezone.now():
            return JsonResponse({
                "status": "error",
                "message": "No se puede agendar en un horario que ya pasó. Por favor, seleccione un horario futuro."
            }, status=410)  # 410 Gone - recurso ya no disponible
        
        # Continuar con el proceso de agendamiento...
        hora_fin_obj = (datetime.combine(datetime.today(), hora_inicio_obj) + timedelta(minutes=30)).time()

        # Verificar si el horario ya está ocupado por otro paciente
        cita_existente = Cita.objects.filter(
            id_horario=horario,
            estado__in=["PENDIENTE", "CONFIRMADA"],
            fecha_hora__time__gte=hora_inicio_obj,
            fecha_hora__time__lt=hora_fin_obj
        ).exists()

        if cita_existente:
            return JsonResponse({
                "status": "error",
                "message": f"La franja {hora_cita} - {hora_fin_obj.strftime('%H:%M')} ya está ocupada."
            }, status=409)

        # Crear la cita
        fecha_hora = datetime.combine(horario.fecha_inicio, hora_inicio_obj)
        
        if timezone.is_aware(fecha_hora):
            fecha_hora = fecha_hora.replace(tzinfo=None)

        cita = Cita.objects.create(
            id_paciente=user,
            id_doctor_id=id_doctor,
            id_horario=horario,
            fecha_hora=fecha_hora,
            motivo=motivo,
            registrado_por=user,
        )

        return JsonResponse({
            "status": "success",
            "message": f"Cita agendada correctamente para el {horario.fecha_inicio.strftime('%d/%m/%Y')} a las {hora_inicio_obj.strftime('%H:%M')}.",
            "id_cita": cita.id_cita,
        })

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"status": "error", "message": f"Error interno: {str(e)}"}, status=500)

# ========== 12) Horario doctor ==========
@login_required
def horario_index(request):
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    
   
    doctores = User.objects.filter(groups__name='Doctor')
    
    return render(request, "horario/index.html", {
        'is_admin': is_admin, 
        'is_doctor': is_doctor,
        'doctores': doctores
    })


@login_required
def horario_formulario(request):
    _id = request.GET.get("id")
    item = None
    if _id:
        try:
            item = HorarioDoctor.objects.get(id_horario=_id)
        except HorarioDoctor.DoesNotExist:
            pass

    is_admin = request.user.groups.filter(name='Administrador').exists()
    is_doctor = request.user.groups.filter(name='Doctor').exists()

    doctores = User.objects.filter(groups__name='Doctor')
    is_admin = request.user.groups.filter(name="Administrador").exists()

    if is_doctor and not is_admin:
        doctores = doctores.filter(id=request.user.id)

    context = {
        'horario': item,
        'doctores': doctores,
        "is_admin": is_admin 
        
    }

# views.py
@login_required
def guardar_disponibilidad(request):
    if request.method != "POST":
        return JsonResponse({
            "success": False,
            "message": "Método no permitido."
        }, status=405)

    try:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"POST data recibido: {request.POST}")
        
        is_admin = request.user.groups.filter(name="Administrador").exists()
        is_doctor = request.user.groups.filter(name="Doctor").exists()

        # Obtener datos del POST
        id_horario = request.POST.get("id_horario")
        id_doctor_post = request.POST.get("id_doctor")
        dia_semana = request.POST.get("dia_semana")
        hora_inicio = request.POST.get("hora_inicio")
        hora_fin = request.POST.get("hora_fin")
        fecha_inicio = request.POST.get("fecha_inicio")
        fecha_fin = request.POST.get("fecha_fin")
        es_recurrente = request.POST.get("es_recurrente") in ["true", "on", "1", True]

        # DEBUG: Log los datos recibidos
        logger.info(f"is_admin: {is_admin}, id_doctor_post: {id_doctor_post}")
        logger.info(f"Datos recibidos - dia_semana: {dia_semana}, hora_inicio: {hora_inicio}")

        # Validaciones básicas
        if not all([dia_semana, hora_inicio, hora_fin, fecha_inicio, fecha_fin]):
            return JsonResponse({
                "success": False,
                "message": "Todos los campos son obligatorios."
            }, status=400)

        # Día de la semana válido
        dias_validos = [
            "Lunes", "Martes", "Miercoles",
            "Jueves", "Viernes", "Sabado", "Domingo"
        ]
        if dia_semana not in dias_validos:
            return JsonResponse({
                "success": False,
                "message": "Día de la semana inválido."
            }, status=400)

        # Parseo de fechas y horas
        hora_inicio = datetime.strptime(hora_inicio, "%H:%M").time()
        hora_fin = datetime.strptime(hora_fin, "%H:%M").time()
        fecha_inicio = datetime.strptime(fecha_inicio, "%Y-%m-%d").date()
        fecha_fin = datetime.strptime(fecha_fin, "%Y-%m-%d").date()

        if hora_inicio >= hora_fin:
            return JsonResponse({
                "success": False,
                "message": "La hora de inicio debe ser menor que la hora fin."
            }, status=400)

        if fecha_inicio > fecha_fin:
            return JsonResponse({
                "success": False,
                "message": "La fecha inicio debe ser menor o igual a la fecha fin."
            }, status=400)

        # Determinación del doctor
        if is_admin:
            logger.info(f"Admin: id_doctor_post = {id_doctor_post}")
            if not id_doctor_post:
                return JsonResponse({
                    "success": False,
                    "message": "Debe seleccionar un doctor."
                }, status=400)

            doctor = User.objects.filter(
                id=id_doctor_post,
                groups__name="Doctor"
            ).first()

            logger.info(f"Doctor encontrado: {doctor}")
            if not doctor:
                return JsonResponse({
                    "success": False,
                    "message": "Doctor inválido."
                }, status=400)
        else:
            # Si no es admin, usar el usuario actual
            doctor = request.user
            logger.info(f"No admin: doctor = {doctor}")

        # Editar o crear
        if id_horario:
            horario = HorarioDoctor.objects.filter(
                id_horario=id_horario
            ).first()

            if not horario:
                return JsonResponse({
                    "success": False,
                    "message": "Horario no encontrado."
                }, status=404)

            if not is_admin and horario.id_doctor != request.user:
                return JsonResponse({
                    "success": False,
                    "message": "No autorizado."
                }, status=403)

            horario.id_doctor = doctor
            horario.dia_semana = dia_semana
            horario.hora_inicio = hora_inicio
            horario.hora_fin = hora_fin
            horario.fecha_inicio = fecha_inicio
            horario.fecha_fin = fecha_fin
            horario.es_recurrente = es_recurrente
            horario.save()

            mensaje = "Horario actualizado correctamente."
        else:
            horario = HorarioDoctor.objects.create(
                id_doctor=doctor,
                dia_semana=dia_semana,
                hora_inicio=hora_inicio,
                hora_fin=hora_fin,
                fecha_inicio=fecha_inicio,
                fecha_fin=fecha_fin,
                es_recurrente=es_recurrente,
                tipo_horario="TRABAJO"
            )

            mensaje = "Horario creado correctamente."

        # Respuesta
        return JsonResponse({
            "success": True,
            "message": mensaje,
            "data": {
                "id_horario": horario.id_horario,
                "doctor_id": horario.id_doctor.id,
                "doctor_nombre": f"{horario.id_doctor.first_name} {horario.id_doctor.last_name}",
                "dia_semana": horario.dia_semana,
                "hora_inicio": horario.hora_inicio.strftime("%H:%M"),
                "hora_fin": horario.hora_fin.strftime("%H:%M"),
                "fecha_inicio": horario.fecha_inicio.strftime("%Y-%m-%d"),
                "fecha_fin": horario.fecha_fin.strftime("%Y-%m-%d"),
                "es_recurrente": bool(horario.es_recurrente),
                "tipo_horario": horario.tipo_horario
            }
        })

    except Exception as e:
        logger.error(f"Error en guardar_disponibilidad: {e}")
        return JsonResponse({
            "success": False,
            "message": f"Error interno: {str(e)}"
        }, status=500)

@login_required
@csrf_exempt
def horario_eliminar(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Método no permitido"}, status=405)

    _id = request.POST.get("id")
    try:
        horario = HorarioDoctor.objects.filter(id_horario=_id).first()
        if horario:
            horario.delete()
            return JsonResponse({"success": True, "message": "Horario eliminado"})
        else:
            return JsonResponse({"success": False, "message": "Horario no encontrado"}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "message": f"No se pudo eliminar: {str(e)}"}, status=400)

@login_required
def horario_calendario(request):
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()

    doctores = User.objects.filter(groups__name='Doctor')
    
    if is_doctor and not is_admin:
        doctores = doctores.filter(id=request.user.id)

    is_paciente = request.user.groups.filter(name="Paciente").exists()
    return render(request, "horario/calendario.html", {
        'is_admin': is_admin,
        'is_doctor': is_doctor,
        'is_paciente': is_paciente,
        'user_id': request.user.id,
        'doctores': doctores
    })

@login_required
def horario_eventos(request):
    """Devuelve eventos de disponibilidad para el doctor en el rango solicitado."""
    doctor_id = request.GET.get('doctor_id')
    start = request.GET.get('start')
    end = request.GET.get('end')

    if not start or not end:
        return JsonResponse([], safe=False)

    try:
        start_dt = parse_datetime(start)
        end_dt = parse_datetime(end)
        if start_dt is None:
            
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
    except Exception:
        
        start_dt = timezone.make_aware(datetime.strptime(start[:19], "%Y-%m-%dT%H:%M:%S"), timezone.get_default_timezone())
        end_dt = timezone.make_aware(datetime.strptime(end[:19], "%Y-%m-%dT%H:%M:%S"), timezone.get_default_timezone())

 
    start_date = start_dt.date()
    end_date = end_dt.date()

    
    hoy = date.today()

    qs = HorarioDoctor.objects.filter(fecha_fin__gte=hoy)
    if doctor_id:
        qs = qs.filter(id_doctor_id=doctor_id)

    weekday_to_db = {
        0: 'Lunes', 1: 'Martes', 2: 'Miercoles', 3: 'Jueves', 4: 'Viernes', 5: 'Sabado', 6: 'Domingo'
    }

    eventos = []
    for h in qs:
        periodo_inicio = max(h.fecha_inicio, start_date)
        periodo_fin = min(h.fecha_fin, end_date)
        if periodo_inicio > periodo_fin:
            continue

        cur = periodo_inicio
        while cur <= periodo_fin:
            if weekday_to_db[cur.weekday()] == h.dia_semana:
                
                start_dt_event = datetime.combine(cur, h.hora_inicio)
                end_dt_event = datetime.combine(cur, h.hora_fin)

                if timezone.is_naive(start_dt_event):
                    start_dt_event = timezone.make_aware(start_dt_event, timezone.get_default_timezone())
                    end_dt_event = timezone.make_aware(end_dt_event, timezone.get_default_timezone())

                eventos.append({
                    'id': f'hor_{h.id_horario}_{cur.isoformat()}',
                    'title': 'Disponible',
                    'start': start_dt_event.isoformat(),
                    'end': end_dt_event.isoformat(),
                    'color': '#2ecc71',
                    'extendedProps': {
                        'id_horario': h.id_horario,
                        'doctor_id': h.id_doctor.id,
                        'tipo': 'disponible'
                    }
                })
            cur += timedelta(days=1)

    return JsonResponse(eventos, safe=False)

@login_required
def horario_formulario(request):
    _id = request.GET.get("id")
    horario = None
    if _id:
        horario = get_object_or_404(HorarioDoctor, id_horario=_id)
        if not (request.user.groups.filter(name="Administrador").exists() or horario.id_doctor_id == request.user.id):
            raise PermissionDenied

    today = date.today().isoformat()
    doctores = User.objects.filter(groups__name='Doctor')
    is_admin = request.user.groups.filter(name="Administrador").exists()
    
  
    if request.user.groups.filter(name="Doctor").exists() and not is_admin:
        doctores = doctores.filter(id=request.user.id)

    return render(request, "horario/form.html", {
        "horario": horario,
        "doctores": doctores,
        "today": today,
        "is_admin": is_admin  
    })

@login_required
def horario_disponibilidad(request):
    doctor_id = request.GET.get('doctor_id')
    start = request.GET.get('start')
    end = request.GET.get('end')
    slot_minutes = int(request.GET.get('slot_minutes') or 30)

    if not doctor_id or not start or not end:
        return JsonResponse([], safe=False)

    start_dt = parse_datetime(start)
    end_dt = parse_datetime(end)
    if start_dt is None or end_dt is None:
        return JsonResponse([], safe=False)

    if timezone.is_naive(start_dt):
        start_dt = timezone.make_aware(start_dt, timezone.get_default_timezone())
    else:
        start_dt = timezone.localtime(start_dt, timezone.get_default_timezone())
    if timezone.is_naive(end_dt):
        end_dt = timezone.make_aware(end_dt, timezone.get_default_timezone())
    else:
        end_dt = timezone.localtime(end_dt, timezone.get_default_timezone())

    hoy = date.today()

    qs = HorarioDoctor.objects.filter(
        id_doctor_id=doctor_id,
        fecha_fin__gte=hoy
    )
  
    citas_qs = Cita.objects.filter(id_doctor_id=doctor_id, fecha_hora__gte=start_dt, fecha_hora__lt=end_dt)
    occupied = set(c.fecha_hora.replace(second=0, microsecond=0) for c in citas_qs)

    eventos = []
    cur_date = start_dt.date()
    end_date = end_dt.date()
    weekday_to_db = {0:'Lunes',1:'Martes',2:'Miercoles',3:'Jueves',4:'Viernes',5:'Sabado',6:'Domingo'}

    while cur_date <= end_date:
        horarios_dia = qs.filter(dia_semana=weekday_to_db[cur_date.weekday()], fecha_inicio__lte=cur_date, fecha_fin__gte=cur_date)
        for h in horarios_dia:
            start_time_naive = datetime.datetime.combine(cur_date, h.hora_inicio)
            end_time_naive = datetime.datetime.combine(cur_date, h.hora_fin)
            if timezone.is_naive(start_time_naive):
                start_time = timezone.make_aware(start_time_naive, timezone.get_default_timezone())
                end_time = timezone.make_aware(end_time_naive, timezone.get_default_timezone())
            else:
                start_time = timezone.localtime(start_time_naive, timezone.get_default_timezone())
                end_time = timezone.localtime(end_time_naive, timezone.get_default_timezone())

            slot_start = start_time
            while slot_start + timedelta(minutes=slot_minutes) <= end_time:
                slot_norm = slot_start.replace(second=0, microsecond=0)
                if slot_norm not in occupied:
                    slot_end = slot_start + timedelta(minutes=slot_minutes)
                    eventos.append({
                        'id': f"slot_{h.id_horario}_{slot_start.isoformat()}",
                        'title': 'Disponible',
                        'start': slot_start.isoformat(),
                        'end': slot_end.isoformat(),
                        'extendedProps': {
                            'id_horario': h.id_horario,
                            'doctor_id': h.id_doctor.id,
                            'tipo': 'slot'
                        },
                        'color': get_color_for_doctor(h.id_doctor.id)
                    })
                slot_start += timedelta(minutes=slot_minutes)
        cur_date += timedelta(days=1)
    return JsonResponse(eventos, safe=False)
@login_required
def horario_listar(request):
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()

    hoy = date.today()

    qs = HorarioDoctor.objects.filter(fecha_fin__gte=hoy)
    if is_doctor and not is_admin:
        qs = qs.filter(id_doctor_id=request.user.id)

    doctor_id = request.GET.get('doctor_id')
    if doctor_id:
        qs = qs.filter(id_doctor_id=doctor_id)

    data = []
    for h in qs.order_by('id_doctor', 'dia_semana', 'hora_inicio'):
        data.append({
            "id_horario": h.id_horario,
            "doctor_id": h.id_doctor.id,
            "doctor_nombre": f"{h.id_doctor.first_name} {h.id_doctor.last_name}",
            "dia_semana": h.dia_semana,
            "hora_inicio": h.hora_inicio.strftime("%H:%M"),
            "hora_fin": h.hora_fin.strftime("%H:%M"),
            "fecha_inicio": h.fecha_inicio.isoformat(),
            "fecha_fin": h.fecha_fin.isoformat(),
            "es_recurrente": bool(h.es_recurrente),
            "tipo_horario": h.tipo_horario
        })

    return JsonResponse({"data": data})

def get_color_for_doctor(doctor_id):
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e']
    return colors[doctor_id % len(colors)]
# ================= CHATBOT MEDICO ==============

@require_POST
@csrf_exempt
def chatbot_api(request):
    try:
        data = json.loads(request.body)
        user_message = data.get('message', '').lower()
        
        # 1. DETECTAR QUÉ INFORMACIÓN NECESITA
        necesita_db, tipo_consulta = detectar_tipo_consulta(user_message)
        
        # 2. OBTENER DATOS DE LA BASE DE DATOS (si es necesario)
        datos_db = ""
        if necesita_db:
            datos_db = obtener_datos_clinica(tipo_consulta, user_message, request)
        
        # Configuración de la API de DeepSeek
        deepseek_api_key = getattr(settings, 'DEEPSEEK_API_KEY', 'sk-7ac68763daa7413f911f3c0b6fd7f4b7')
        deepseek_url = 'https://api.deepseek.com/v1/chat/completions'
        
        headers = {
            'Authorization': f'Bearer {deepseek_api_key}',
            'Content-Type': 'application/json'
        }
       
        # Prompt del sistema MODIFICADO con datos dinámicos
        system_prompt = f"""
            Eres JOAD MEDIC, asistente virtual de Medessentia.
            INFORMACIÓN OFICIAL DE LA CLÍNICA (OBLIGATORIA):
            - Nombre: Medessentia
            - Teléfono: 0991043977
            - Dirección: Av. Abdón Calderón y Mariscal Sucre Cantón Saquisilí

            REGLAS ABSOLUTAS (OBLIGATORIAS):
            - NUNCA inventes teléfonos, direcciones o contactos.
            - SOLO puedes mencionar doctores que aparezcan en la sección "INFORMACIÓN REAL DE LA BASE DE DATOS".
            - SI NO HAY doctores listados, debes decir exactamente: "Actualmente solo atiende la Dra. Alexandra Toapanta."
            - PROHIBIDO inventar nombres de médicos, especialistas o técnicos.
            - PROHIBIDO mencionar personas que no existan en la base de datos.
            - Si el usuario pregunta por doctores y solo hay uno, debes indicarlo claramente.

            INFORMACIÓN REAL DE LA BASE DE DATOS (ÚNICA FUENTE VÁLIDA):
            {datos_db}

            INSTRUCCIONES ESPECÍFICAS PARA AGENDAMIENTO:
            1. Cuando el usuario quiera agendar una cita, sigue este flujo:
            - Paso 1: Confirmar que quiere agendar cita
            - Paso 2: Preguntar tipo de consulta (general, neonatal, análisis)
            - Paso 3: Guiar al sistema de agendamiento real

            2. NO intentes procesar la cita directamente en el chat
            3. Siempre deriva al sistema real cuando el usuario esté listo

            FLUJO DE AGENDAMIENTO:
            - Usuario: "Quiero agendar cita" → Tú: "¡Perfecto! Te ayudo con eso. ¿Qué tipo de consulta necesitas? Tenemos: 👨‍⚕️ Consulta General, 👶 Atención Neonatal, 🧪 Análisis Clínicos"
            - Usuario elige tipo → Tú: "Excelente elección. Para agendar tu cita de [tipo], necesitas usar nuestro sistema de reservas. ¿Quieres que te lleve allí ahora?"

            

            RESPUESTAS INTELIGENTES:
            - Para "agendar cita": "¡Claro! Te ayudo con el agendamiento. ¿Qué tipo de consulta necesitas?"
            - Después de elegir tipo: "Perfecto. Para seleccionar fecha y doctor, necesitas acceder a nuestro sistema de agendamiento. ¿Quieres que te lleve allí ahora? [SÍ/NO]"
            - Para "sí": "Excelente. Te redirijo al sistema de agendamiento..."
            - Para dudas: "Puedo responder tus preguntas sobre horarios y servicios, pero para reservar necesitas usar nuestro sistema seguro."

            IMPORTANTE: Siempre deriva al sistema real para el agendamiento final.
            NO puedes dar diagnósticos médicos
            NO puedes recetar medicamentos
            NO puedes interpretar resultados de exámenes
            Siempre recomienda consultar con un profesional de la salud para casos específicos
            Para emergencias médicas, indica que contacten directamente con la clínica
            """
        
        payload = {
            'model': 'deepseek-chat',
            'messages': [
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_message
                }
            ],
            'max_tokens': 500,
            'temperature': 0.7
        }
        
        response = requests.post(deepseek_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        response_data = response.json()
        
        bot_response = response_data['choices'][0]['message']['content']
        
        return JsonResponse({'response': bot_response})
        
    except requests.exceptions.Timeout:
        return JsonResponse({
            'response': 'Lo siento, el servicio está tardando en responder. Por favor, intenta nuevamente en un momento.'
        }, status=408)
        
    except requests.exceptions.RequestException as e:
        print(f"Error en la API de DeepSeek: {e}")
        return JsonResponse({
            'response': 'Lo siento, estoy teniendo dificultades técnicas. Por favor, contacta directamente con nuestra clínica al 0991043977.'
        }, status=503)
        
    except Exception as e:
        print(f"Error general: {e}")
        return JsonResponse({
            'response': 'Ha ocurrido un error inesperado. Por favor, intenta nuevamente o contacta con nosotros directamente.'
        }, status=500)

# ============ FUNCIONES AUXILIARES PARA ACCEDER A LA DB ============

def detectar_tipo_consulta(mensaje):
    """Detecta qué tipo de información necesita el usuario"""
    mensaje = mensaje.lower()
    
    # Palabras clave para cada tipo de consulta
    if any(palabra in mensaje for palabra in ['doctores', 'médicos', 'doctor', 'quien atiende', 'especialista']):
        return True, 'doctores'
    
    elif any(palabra in mensaje for palabra in ['horarios', 'disponibilidad', 'cuándo atienden', 'días', 'horas']):
        return True, 'horarios'
    
    elif any(palabra in mensaje for palabra in ['mis citas', 'tengo cita', 'citas programadas', 'próxima cita']):
        return True, 'mis_citas'
    
    elif any(palabra in mensaje for palabra in ['agendar', 'reservar', 'nueva cita', 'pedir cita']):
        return True, 'agendar'
    
    elif any(palabra in mensaje for palabra in ['servicios', 'qué ofrecen', 'precios', 'costos', 'valor']):
        return True, 'servicios'
    
    return False, None

def obtener_datos_clinica(tipo_consulta, mensaje, request):
    """Obtiene datos reales de la base de datos según la consulta"""

    hoy = date.today()

    # ================= DOCTORA =================
    if tipo_consulta == 'doctores':
        doctores = User.objects.filter(
            groups__name='Doctor',
            is_active=True,
            first_name__iexact='Alexandra',
            last_name__icontains='Toapanta'
        )

        if doctores.exists():
            doc = doctores.first()
            nombre = f"Dra. {doc.first_name} {doc.last_name}"
            return (
                "👩‍⚕️ DOCTORA DISPONIBLE:\n"
                f"- {nombre}\n\n"
                "Actualmente Medessentia atiende únicamente con esta doctora."
            )

        return "Actualmente no hay doctores disponibles."

    # ================= HORARIOS =================
    elif tipo_consulta == 'horarios':
        hoy = date.today()

        horarios = HorarioDoctor.objects.filter(
            tipo_horario='TRABAJO',
            fecha_fin__gte=hoy
        ).order_by('dia_semana', 'hora_inicio')

        if not horarios.exists():
            return "Actualmente no hay horarios de atención vigentes registrados en el sistema."

        dias_atencion = {}

        for h in horarios:
            dia = h.dia_semana
            rango = f"{h.hora_inicio.strftime('%H:%M')} a {h.hora_fin.strftime('%H:%M')}"
            dias_atencion.setdefault(dia, set()).add(rango)

        respuesta = "🕒 **Horarios de atención vigentes desde hoy:**\n\n"

        for dia, rangos in dias_atencion.items():
            respuesta += f"- **{dia}**: " + ", ".join(sorted(rangos)) + "\n"

        respuesta += (
            "\n📅 *La disponibilidad exacta por fecha y hora se muestra en el "
            "sistema de agendamiento.*\n"
            "👉 Ingresa al calendario para ver los turnos disponibles y agendar tu cita."
        )

        return respuesta


    # ================= MIS CITAS =================
    elif tipo_consulta == 'mis_citas' and request.user.is_authenticated:
        citas = Cita.objects.filter(
            id_paciente=request.user,
            estado__in=['PENDIENTE', 'CONFIRMADA'],
            fecha_hora__gte=datetime.now()
        ).select_related('id_doctor').order_by('fecha_hora')

        if citas.exists():
            info = "📅 TUS PRÓXIMAS CITAS:\n"
            for cita in citas:
                fecha = cita.fecha_hora.strftime('%d/%m/%Y %H:%M')
                doctor = f"Dra. {cita.id_doctor.first_name} {cita.id_doctor.last_name}"
                info += f"- {fecha} con {doctor}\n"
            return info

        return "No tienes citas programadas."

    # ================= AGENDAR =================
    elif tipo_consulta == 'agendar':
        total = HorarioDoctor.objects.filter(
            tipo_horario='TRABAJO',
            fecha_inicio__gte=hoy
        ).count()

        return (
            "📋 Para agendar una cita debes usar el sistema de reservas.\n"
            f"Actualmente hay {total} horarios disponibles."
        )

    return ""

#para automatizar citas 
@login_required
def chatbot_redirigir_agendamiento(request):
    """Redirige al usuario al proceso de agendamiento desde el chatbot"""
    tipo_consulta = request.GET.get('tipo', 'general')
    
    # CONSULTAR DOCTORES DISPONIBLES para redirección más inteligente
    doctores_disponibles = User.objects.filter(
        groups__name='Doctor',
        is_active=True
    ).values('id', 'first_name', 'last_name', 'email')
    
    # Guardar en sesión para usar después
    request.session['tipo_consulta_chatbot'] = tipo_consulta
    request.session['doctores_disponibles'] = list(doctores_disponibles)
    
    return redirect('elegir_doctor')

@login_required
def chatbot_info_agendamiento(request):
    """Endpoint que devuelve información útil para el chatbot"""
    
    # CONSULTAR DATOS EN TIEMPO REAL
    hoy = date.today()
    
    # Contar doctores activos
    doctores_count = User.objects.filter(
        groups__name='Doctor',
        is_active=True
    ).count()
    
    # Horarios disponibles próximos 7 días
    proxima_semana = hoy + timedelta(days=7)
    horarios_count = HorarioDoctor.objects.filter(
        fecha_inicio__range=[hoy, proxima_semana],
        tipo_horario='TRABAJO'
    ).count()
    
    # Citas próximas del usuario (si está logueado)
    citas_proximas = 0
    if request.user.is_authenticated:
        citas_proximas = Cita.objects.filter(
            id_paciente=request.user,
            fecha_hora__gte=datetime.now(),
            estado__in=['PENDIENTE', 'CONFIRMADA']
        ).count()
    
    return JsonResponse({
        'pasos_agendamiento': [
            '1. Elegir tipo de consulta',
            '2. Seleccionar doctor', 
            '3. Elegir fecha y hora',
            '4. Confirmar cita'
        ],
        'horarios': 'Lunes a Viernes: 8:00-18:00, Sábados: 8:00-12:00',
        'servicios': ['Consulta General', 'Atención Neonatal', 'Análisis Clínicos'],
        'contacto': '0991043977',
        'estadisticas': {
            'doctores_activos': doctores_count,
            'horarios_proxima_semana': horarios_count,
            'tus_citas_proximas': citas_proximas,
            'fecha_consulta': hoy.strftime('%d/%m/%Y')
        }
    })
@login_required
def inicio_historiaclinica(request):
    return render(request, 'historia_clinica/inicio.html')
@login_required
def listado_historias(request):
    try:
        search_term = request.GET.get('q', '').strip()
        
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'No autenticado'}, status=401)
        
        # Consulta básica con select_related
        historias = HistoriaClinica.objects.select_related(
            'id_paciente',  # Cambiado de 'id_paciente_id' a 'id_paciente'
            'creado_por'
        ).all()
        
        if search_term:
            historias = historias.filter(
                Q(nombres_completos__icontains=search_term) |
                Q(expediente_no__icontains=search_term) |
                Q(cedula__icontains=search_term) |
                Q(id_paciente__first_name__icontains=search_term) |
                Q(id_paciente__last_name__icontains=search_term)
            )
        
        data = []
        for historia in historias.order_by('-fecha_creacion'):
            # Calcular edad
            edad = None
            if historia.fecha_nacimiento:
                hoy = date.today()
                edad = hoy.year - historia.fecha_nacimiento.year
                if hoy.month < historia.fecha_nacimiento.month or \
                   (hoy.month == historia.fecha_nacimiento.month and hoy.day < historia.fecha_nacimiento.day):
                    edad -= 1
            
            # Obtener nombre del paciente
            paciente_nombre = historia.nombres_completos
            if not paciente_nombre:
                paciente_nombre = f"{historia.id_paciente.first_name or ''} {historia.id_paciente.last_name or ''}".strip()
                if not paciente_nombre:
                    paciente_nombre = historia.id_paciente.username
            
            data.append({
                'id_historia': historia.id_historia,
                'expediente_no': historia.expediente_no or 'Sin expediente',
                'paciente_nombre': paciente_nombre,
                'paciente_cedula': historia.cedula or 'No registrada',
                'creado_por': historia.creado_por.get_full_name() or historia.creado_por.username,
                'fecha_creacion': historia.fecha_creacion.strftime('%d/%m/%Y'),
                'edad': str(edad) if edad else 'N/D',
                'sexo': historia.sexo_biologico or '',
                'telefono': historia.telefono or 'Sin teléfono',
                'tipo_seguro': historia.tipo_seguro or 'NINGUNO',
                'puede_editar': True,
                'puede_eliminar': True,
            })
        
        return JsonResponse({
            'data': data,
            'recordsTotal': len(data),
            'recordsFiltered': len(data)
        })
        
    except Exception as e:
        print(f"ERROR en listado_historias: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({
            'data': [],
            'recordsTotal': 0,
            'recordsFiltered': 0
        })

# AJAX: Obtener formulario
@login_required
def obtener_formulario(request):
    try:
        historia_id = request.GET.get('id', '')
        historia = None
        
        if historia_id and historia_id != 'undefined':
            try:
                historia = HistoriaClinica.objects.get(id_historia=historia_id)
            except HistoriaClinica.DoesNotExist:
                historia = None
        
        context = {
            'historia': historia,
            'usuario_actual': request.user,
        }
        
        form_html = render_to_string('historia_clinica/formulario.html', context, request=request)
        return JsonResponse({'form_html': form_html})
        
    except Exception as e:
        print(f"ERROR en obtener_formulario: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': 'Error al cargar formulario'}, status=500)

# AJAX: Guardar historia
@login_required
def guardar_historia(request):
    try:
        data = json.loads(request.body)
        historia_id = data.get('id_historia')
        
        with transaction.atomic():
            if historia_id:
                historia = HistoriaClinica.objects.get(id_historia=historia_id)
                historia.actualizado_por = request.user
            else:
                historia = HistoriaClinica()
                historia.creado_por = request.user
            
            # *** CORRECCIÓN AQUÍ: Obtener el objeto User, no solo el ID ***
            paciente_id = data.get('paciente_id')
            if paciente_id:
                try:
                    paciente = User.objects.get(id=int(paciente_id))
                    historia.id_paciente = paciente  # Asignar objeto User, no ID
                except (ValueError, User.DoesNotExist) as e:
                    return JsonResponse({
                        'success': False, 
                        'error': f'Paciente no válido: {str(e)}'
                    }, status=400)
            else:
                return JsonResponse({
                    'success': False, 
                    'error': 'ID de paciente requerido'
                }, status=400)
            
            # Resto de los campos...
            historia.expediente_no = data.get('expediente_no')
            historia.nombres_completos = data.get('nombres_completos')
            historia.cedula = data.get('cedula')
            
            # Fecha nacimiento
            fecha_nac = data.get('fecha_nacimiento')
            if fecha_nac:
                historia.fecha_nacimiento = datetime.strptime(fecha_nac, '%Y-%m-%d').date()
            
            # Demográficos
            historia.sexo_biologico = data.get('sexo_biologico')
            historia.genero = data.get('genero')
            historia.estado_civil = data.get('estado_civil')
            
            # Contacto
            historia.direccion = data.get('direccion')
            historia.telefono = data.get('telefono')
            historia.email = data.get('email')
            historia.contacto_emergencia = data.get('contacto_emergencia')
            
            # Social
            historia.nivel_instruccion = data.get('nivel_instruccion')
            historia.ocupacion = data.get('ocupacion')
            historia.tipo_seguro = data.get('tipo_seguro') or 'NINGUNO'
            
            # Antecedentes
            historia.antecedentes_personales = data.get('antecedentes_personales')
            historia.antecedentes_familiares = data.get('antecedentes_familiares')
            historia.antecedentes_obstetricos = data.get('antecedentes_obstetricos')
            historia.antecedentes_ginecologicos = data.get('antecedentes_ginecologicos')
            historia.vacunacion = data.get('vacunacion')
            
            historia.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Historia clínica guardada exitosamente',
                'id_historia': historia.id_historia
            })
            
    except Exception as e:
        print(f"ERROR en guardar_historia: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
# AJAX: Detalles
@login_required
def detalle_historia(request, id):
    try:
        historia = HistoriaClinica.objects.get(id_historia=id)
        
        # Calcular edad
        edad = None
        if historia.fecha_nacimiento:
            hoy = date.today()
            edad = hoy.year - historia.fecha_nacimiento.year
            if hoy.month < historia.fecha_nacimiento.month or \
               (hoy.month == historia.fecha_nacimiento.month and hoy.day < historia.fecha_nacimiento.day):
                edad -= 1
        
        datos = {
            'expediente_no': historia.expediente_no,
            'nombres_completos': historia.nombres_completos or f"{historia.id_paciente.first_name} {historia.id_paciente.last_name}",
            'cedula': historia.cedula or 'No registrada',
            'fecha_nacimiento': historia.fecha_nacimiento.strftime('%d/%m/%Y') if historia.fecha_nacimiento else 'No especificada',
            'edad': str(edad) if edad else 'No calculable',
            'sexo_biologico': historia.sexo_biologico or 'No especificado',
            'genero': historia.genero or 'No especificado',
            'estado_civil': historia.estado_civil or 'No especificado',
            'direccion': historia.direccion or 'No especificada',
            'telefono': historia.telefono or 'No especificado',
            'email': historia.email or 'No especificado',
            'contacto_emergencia': historia.contacto_emergencia or 'No especificado',
            'nivel_instruccion': historia.nivel_instruccion or 'No especificado',
            'ocupacion': historia.ocupacion or 'No especificada',
            'tipo_seguro': historia.tipo_seguro or 'NINGUNO',
            'antecedentes_personales': historia.antecedentes_personales or 'Sin registros',
            'antecedentes_familiares': historia.antecedentes_familiares or 'Sin registros',
            'antecedentes_obstetricos': historia.antecedentes_obstetricos or 'N/A',
            'antecedentes_ginecologicos': historia.antecedentes_ginecologicos or 'N/A',
            'vacunacion': historia.vacunacion or 'Sin registros',
        
            'fecha_creacion': historia.fecha_creacion.strftime('%d/%m/%Y %H:%M'),
            'creado_por': historia.creado_por.get_full_name() or historia.creado_por.username,
            'actualizado_por': historia.actualizado_por.get_full_name() if historia.actualizado_por else None,
            'fecha_actualizacion': historia.fecha_actualizacion.strftime('%d/%m/%Y %H:%M') if historia.actualizado_por else None,
        }
        
        return JsonResponse({'data': datos})
        
    except Exception as e:
        print(f"ERROR en detalle_historia: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': 'Historia no encontrada'}, status=404)

# AJAX: Eliminar
@login_required
def eliminar_historia(request):
    try:
        data = json.loads(request.body)
        historia_id = data.get('id')
        
        historia = HistoriaClinica.objects.get(id_historia=historia_id)
        historia.delete()
        
        return JsonResponse({'success': True, 'message': 'Historia eliminada'})
        
    except Exception as e:
        print(f"ERROR en eliminar_historia: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# AJAX: Buscar pacientes - *** CORREGIDO ***
@login_required
def buscar_pacientes(request):
    try:
        query = request.GET.get('q', '').strip()
        
        print(f"🔍 Buscando pacientes con: '{query}'")
        
        if len(query) < 2:
            return JsonResponse({'data': []})
        
        # Normalizar query para búsqueda más flexible
        query_normalizado = query.lower()
        
        # 1. Buscar en el grupo Paciente
        try:
            grupo_paciente = Group.objects.get(name='Paciente')
            usuarios_base = grupo_paciente.user_set.all()
            print(f"✅ Grupo 'Paciente' encontrado con {usuarios_base.count()} usuarios")
        except Group.DoesNotExist:
            usuarios_base = User.objects.filter(is_staff=False, is_superuser=False)
            print(f"⚠️ Grupo 'Paciente' no existe, usando usuarios normales: {usuarios_base.count()}")
        
        # 2. Búsqueda múltiple con OR
        usuarios_filtrados = usuarios_base.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(username__icontains=query) |
            Q(email__icontains=query)
        ).distinct()
        
        print(f"📋 Usuarios filtrados por nombre/username: {usuarios_filtrados.count()}")
        
        # 3. Buscar también por cédula en PerfilUsuario
        perfiles_cedula = PerfilUsuario.objects.filter(
            cedula_usuario__icontains=query
        ).select_related('user')
        
        usuarios_por_cedula = [perfil.user for perfil in perfiles_cedula]
        print(f"🆔 Usuarios encontrados por cédula: {len(usuarios_por_cedula)}")
        
        # 4. Combinar resultados sin duplicados
        usuarios_dict = {}
        
        # Agregar usuarios filtrados
        for usuario in usuarios_filtrados:
            usuarios_dict[usuario.id] = usuario
        
        # Agregar usuarios por cédula
        for usuario in usuarios_por_cedula:
            if usuario.id not in usuarios_dict:
                usuarios_dict[usuario.id] = usuario
        
        usuarios_finales = list(usuarios_dict.values())
        print(f"✨ Total usuarios únicos encontrados: {len(usuarios_finales)}")
        
        # 5. Ordenar por relevancia (primero los que coinciden con el inicio del nombre)
        def score_relevancia(usuario):
            score = 0
            nombre_completo = f"{usuario.first_name} {usuario.last_name}".lower()
            
            # Mayor score si el query está al inicio
            if nombre_completo.startswith(query_normalizado):
                score += 100
            elif query_normalizado in nombre_completo:
                score += 50
            
            # Bonus si coincide con username
            if usuario.username.lower().startswith(query_normalizado):
                score += 75
            
            return score
        
        usuarios_finales.sort(key=score_relevancia, reverse=True)
        
        # 6. Limitar a 20 resultados (aumentado desde 10)
        usuarios_finales = usuarios_finales[:20]
        
        # 7. Construir respuesta
        data = []
        for usuario in usuarios_finales:
            try:
                perfil = PerfilUsuario.objects.get(user=usuario)
                cedula = perfil.cedula_usuario or 'Sin cédula'
                telefono = perfil.telefono_usuario or 'Sin teléfono'
            except PerfilUsuario.DoesNotExist:
                cedula = 'Sin cédula'
                telefono = 'Sin teléfono'
            
            tiene_historia = HistoriaClinica.objects.filter(id_paciente=usuario).exists()
            
            nombre_completo = f"{usuario.first_name or ''} {usuario.last_name or ''}".strip()
            if not nombre_completo:
                nombre_completo = usuario.username
            
            data.append({
                'id': usuario.id,
                'nombre_completo': nombre_completo,
                'cedula': cedula,
                'telefono': telefono,
                'email': usuario.email or 'Sin email',
                'tiene_historia': tiene_historia,
                'username': usuario.username
            })
        
        print(f"📤 Retornando {len(data)} pacientes al frontend")
        return JsonResponse({'data': data, 'total': len(data)})
        
    except Exception as e:
        import traceback
        print(f"❌ Error en buscar_pacientes: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'data': [], 'error': str(e)}, status=500)
# AJAX: Crear paciente rápido - CORREGIDO
@login_required
def crear_paciente_rapido(request):
    try:
        data = json.loads(request.body)

        nombres = data.get('nombres', '').strip()
        apellidos = data.get('apellidos', '').strip()
        cedula = data.get('cedula', '').strip()
        telefono = data.get('telefono', '').strip()

        if not nombres or not apellidos:
            return JsonResponse({'success': False, 'error': 'Nombres y apellidos son obligatorios'})

        # 🔍 BUSCAR SI YA EXISTE POR CÉDULA
        if cedula:
            perfil_existente = PerfilUsuario.objects.filter(cedula_usuario=cedula).select_related('user').first()
            if perfil_existente:
                user = perfil_existente.user
                return JsonResponse({
                    'success': True,
                    'paciente': {
                        'id': user.id,
                        'nombre_completo': f"{user.first_name} {user.last_name}",
                        'cedula': cedula,
                        'telefono': perfil_existente.telefono_usuario,
                    },
                    'message': 'Paciente ya existente'
                })

        # 🆕 CREAR SOLO SI NO EXISTE
        with transaction.atomic():
            username = f"paciente_{datetime.now().strftime('%Y%m%d%H%M%S')}"

            user = User.objects.create_user(
                username=username,
                first_name=nombres,
                last_name=apellidos,
                password=User.objects.make_random_password(),
                is_active=True
            )

            grupo, _ = Group.objects.get_or_create(name='Paciente')
            user.groups.add(grupo)

            PerfilUsuario.objects.create(
                user=user,
                cedula_usuario=cedula if cedula else f"TEMP-{user.id}",
                telefono_usuario=telefono or '0000000000',
                direccion_usuario=''
            )

        return JsonResponse({
            'success': True,
            'paciente': {
                'id': user.id,
                'nombre_completo': f"{nombres} {apellidos}",
                'cedula': cedula or 'Sin cédula',
                'telefono': telefono or 'Sin teléfono',
            },
            'message': 'Paciente creado'
        })

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# AJAX: Generar expediente
@login_required
def generar_expediente(request):
    try:
        fecha_actual = datetime.now()
        fecha_str = fecha_actual.strftime('%Y%m%d')
        
        count_hoy = HistoriaClinica.objects.filter(
            fecha_creacion__date=fecha_actual.date()
        ).count()
        
        numero = str(count_hoy + 1).zfill(4)
        expediente = f"HC-{fecha_str}-{numero}"
        
        return JsonResponse({'expediente': expediente})
        
    except Exception as e:
        print(f"Error en generar_expediente: {str(e)}")
        expediente = f"HC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        return JsonResponse({'expediente': expediente})

# AJAX: Obtener datos del paciente - CORREGIDO
@login_required
def obtener_datos_paciente(request):
    try:
        paciente_id = request.GET.get('paciente_id')
        
        if not paciente_id:
            return JsonResponse({'success': False, 'error': 'ID requerido'})
        
        paciente = User.objects.get(id=int(paciente_id))
        
        # Buscar historia clínica directamente
        try:
            historia = HistoriaClinica.objects.get(id_paciente=paciente)
            datos = {
                'tiene_historia': True,
                'nombres_completos': historia.nombres_completos or f"{paciente.first_name} {paciente.last_name}",
                'cedula': historia.cedula,
                'fecha_nacimiento': historia.fecha_nacimiento.strftime('%Y-%m-%d') if historia.fecha_nacimiento else None,
                'sexo_biologico': historia.sexo_biologico,
                'genero': historia.genero,
                'estado_civil': historia.estado_civil,
                'direccion': historia.direccion,
                'telefono': historia.telefono,
                'email': historia.email,
                'contacto_emergencia': historia.contacto_emergencia,
                'nivel_instruccion': historia.nivel_instruccion,
                'ocupacion': historia.ocupacion,
                'tipo_seguro': historia.tipo_seguro,
                'antecedentes_personales': historia.antecedentes_personales,
                'antecedentes_familiares': historia.antecedentes_familiares,
                'antecedentes_obstetricos': historia.antecedentes_obstetricos,
                'antecedentes_ginecologicos': historia.antecedentes_ginecologicos,
                'vacunacion': historia.vacunacion,
            }
        except HistoriaClinica.DoesNotExist:
            perfil = PerfilUsuario.objects.filter(user=paciente).first()
            datos = {
                'tiene_historia': False,
                'nombres_completos': f"{paciente.first_name} {paciente.last_name}".strip() or paciente.username,
                'cedula': perfil.cedula_usuario if perfil else None,
                'telefono': perfil.telefono_usuario if perfil else None,
                'email': paciente.email,
            }
        
        return JsonResponse({'success': True, 'datos': datos})
        
    except (ValueError, User.DoesNotExist) as e:
        return JsonResponse({'success': False, 'error': f'Paciente no encontrado: {str(e)}'}, status=404)
    except Exception as e:
        print(f"ERROR en obtener_datos_paciente: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
# ========== Inicio prueba cie10 ==========


@login_required
def cie10_inicio(request):
    return render(request, "cie10/inicio.html")

@login_required
def cie10_listado(request):
    try:
        q = request.GET.get("q", "").strip()
        
        queryset = Cie10.objects.all()
        
        if q:
            queryset = queryset.filter(
                Q(codigo__icontains=q) | 
                Q(descripcion__icontains=q)
            )
        
        data = []
        for item in queryset.order_by('codigo'):
            data.append({
                "id_cie10": item.id_cie10,
                "codigo": item.codigo,
                "descripcion": item.descripcion
            })
        
        return JsonResponse({"data": data})
    
    except Exception as e:
        return JsonResponse({"data": [], "error": str(e)})

@login_required
def cie10_formulario(request):
    try:
        item_id = request.GET.get("id")
        item = None
        
        if item_id:
            try:
                item = Cie10.objects.get(id_cie10=item_id)
            except Cie10.DoesNotExist:
                return JsonResponse({"error": "No encontrado"}, status=404)
        
        # Pasar el request para que el CSRF token funcione
        form_html = render_to_string("cie10/formulario.html", {"item": item}, request=request)
        return JsonResponse({"form_html": form_html})
    
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def cie10_guardar(request):
    try:
        # Procesar tanto JSON como FormData
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            codigo = data.get("codigo", "").strip()
            descripcion = data.get("descripcion", "").strip()
            id_cie10 = data.get("id_cie10")
        else:
            # FormData tradicional
            codigo = request.POST.get("codigo", "").strip()
            descripcion = request.POST.get("descripcion", "").strip()
            id_cie10 = request.POST.get("id_cie10")
        
        # Validaciones
        if not codigo:
            return JsonResponse({"success": False, "error": "El código es obligatorio"})
        
        if not descripcion:
            return JsonResponse({"success": False, "error": "La descripción es obligatoria"})
        
        with transaction.atomic():
            if id_cie10:
                # Editar
                item = Cie10.objects.get(id_cie10=id_cie10)
                # Verificar si el código ya existe (excluyendo el actual)
                if Cie10.objects.filter(codigo=codigo).exclude(id_cie10=id_cie10).exists():
                    return JsonResponse({"success": False, "error": "El código ya existe"})
                
                item.codigo = codigo
                item.descripcion = descripcion
                item.save()
                message = "Actualizado correctamente"
            else:
                # Crear
                if Cie10.objects.filter(codigo=codigo).exists():
                    return JsonResponse({"success": False, "error": "El código ya existe"})
                
                item = Cie10.objects.create(codigo=codigo, descripcion=descripcion)
                message = "Creado correctamente"
        
        return JsonResponse({
            "success": True,
            "message": message
        })
        
    except Cie10.DoesNotExist:
        return JsonResponse({"success": False, "error": "Registro no encontrado"})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})

@login_required
@require_http_methods(["POST"])
def cie10_eliminar(request):
    try:
        # Procesar tanto JSON como FormData
        if request.content_type == 'application/json':
            data = json.loads(request.body)
            item_id = data.get("id")
        else:
            item_id = request.POST.get("id")
        
        if not item_id:
            return JsonResponse({"success": False, "error": "ID requerido"})
        
        item = Cie10.objects.get(id_cie10=item_id)
        item.delete()
        
        return JsonResponse({"success": True, "message": "Eliminado correctamente"})
        
    except Cie10.DoesNotExist:
        return JsonResponse({"success": False, "error": "Registro no encontrado"})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)})
# ========== Fin prueba cie10 por el momento==========
# ========== Atención Médica - Views ==========

# Vista principal
@login_required
def inicio_atencion(request):
    return render(request, 'atencion/inicio.html')

# AJAX: Listado de atenciones
@login_required
def listado_atenciones(request):
    try:
        search_term = request.GET.get('q', '').strip()
        historia_id = request.GET.get('historia_id', '')
        
        # Consulta básica
        atenciones = AtencionMedica.objects.select_related(
            'id_historia', 'id_paciente', 'id_doctor'
        ).all()
        
        # Filtrar por historia clínica específica si se proporciona
        if historia_id:
            atenciones = atenciones.filter(id_historia_id=historia_id)
        
        # Búsqueda
        if search_term:
            atenciones = atenciones.filter(
                Q(id_historia__expediente_no__icontains=search_term) |
                Q(id_historia__nombres_completos__icontains=search_term) |
                Q(id_historia__cedula__icontains=search_term) |
                Q(motivo_consulta__icontains=search_term)
            )
        
        data = []
        for atencion in atenciones.order_by('-fecha_atencion'):
            # Obtener nombres
            paciente_nombre = atencion.id_historia.nombres_completos
            if not paciente_nombre:
                paciente_nombre = f"{atencion.id_paciente.first_name} {atencion.id_paciente.last_name}".strip()
            
            data.append({
                'id_atencion': atencion.id_atencion,
                'expediente': atencion.id_historia.expediente_no,
                'paciente': paciente_nombre,
                'cedula': atencion.id_historia.cedula or 'No registrada',
                'doctor': f"{atencion.id_doctor.first_name} {atencion.id_doctor.last_name}",
                'fecha_atencion': atencion.fecha_atencion.strftime('%d/%m/%Y %H:%M'),
                'tipo_atencion': atencion.get_tipo_atencion_display(),
                'motivo_consulta': (atencion.motivo_consulta[:50] + '...') if len(atencion.motivo_consulta) > 50 else atencion.motivo_consulta,
                'diagnostico': atencion.cie10_descripcion or 'Sin diagnóstico',
                'puede_editar': True,
                'puede_eliminar': True,
            })
        
        return JsonResponse({
            'data': data,
            'recordsTotal': len(data),
            'recordsFiltered': len(data)
        })
        
    except Exception as e:
        print(f"ERROR en listado_atenciones: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({
            'data': [],
            'recordsTotal': 0,
            'recordsFiltered': 0
        })

# AJAX: Obtener formulario
@login_required
def obtener_formulario_atencion(request):
    try:
        atencion_id = request.GET.get('id', '')
        historia_id = request.GET.get('historia_id', '')
        atencion = None
        ultimos_signos = None
        
        if atencion_id:
            try:
                atencion = AtencionMedica.objects.get(id_atencion=atencion_id)
            except AtencionMedica.DoesNotExist:
                atencion = None
        elif historia_id:
            # Si se proporciona historia_id, cargar datos del paciente
            try:
                historia = HistoriaClinica.objects.get(id_historia=historia_id)
                # Crear objeto atencion vacío con datos de la historia
                atencion = AtencionMedica(
                    id_historia=historia,
                    id_paciente=historia.id_paciente
                )
                
                # Buscar los últimos signos vitales del paciente
                try:
                    perfil_usuario = PerfilUsuario.objects.get(user=historia.id_paciente)
                    ultimos_signos = SignosVitales.objects.filter(
                        perfil_usuario=perfil_usuario
                    ).order_by('-fecha_registro').first()
                except (PerfilUsuario.DoesNotExist, SignosVitales.DoesNotExist):
                    ultimos_signos = None
                    
            except HistoriaClinica.DoesNotExist:
                pass
        
        context = {
            'atencion': atencion,
            'usuario_actual': request.user,
            'ultimos_signos': ultimos_signos,
        }
        
        form_html = render_to_string('atencion/formulario_atencion.html', context, request=request)
        return JsonResponse({'form_html': form_html})
        
    except Exception as e:
        print(f"ERROR en obtener_formulario_atencion: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': 'Error al cargar formulario'}, status=500)

@login_required
def guardar_atencion(request):
    try:
        # Usar request.POST en lugar de json.loads(request.body)
        data = request.POST
        atencion_id = data.get('id_atencion')
        
        with transaction.atomic():
            if atencion_id and atencion_id != '':
                atencion = AtencionMedica.objects.get(id_atencion=atencion_id)
                atencion.actualizado_por = request.user
            else:
                atencion = AtencionMedica()
                atencion.creado_por = request.user
            
            # Obtener historia clínica
            historia_id = data.get('historia_id')
            if historia_id:
                try:
                    historia = HistoriaClinica.objects.get(id_historia=int(historia_id))
                    atencion.id_historia = historia
                    atencion.id_paciente = historia.id_paciente
                except (ValueError, HistoriaClinica.DoesNotExist) as e:
                    return JsonResponse({
                        'success': False, 
                        'error': f'Historia clínica no válida: {str(e)}'
                    }, status=400)
            else:
                return JsonResponse({
                    'success': False, 
                    'error': 'Historia clínica requerida'
                }, status=400)
            
            # Doctor
            atencion.id_doctor = request.user
            
            # Fecha atención
            fecha_atencion = data.get('fecha_atencion')
            if fecha_atencion:
                try:
                    # Formato: YYYY-MM-DDTHH:MM
                    atencion.fecha_atencion = datetime.strptime(fecha_atencion, '%Y-%m-%dT%H:%M')
                except ValueError:
                    # Si falla, intentar otro formato
                    try:
                        atencion.fecha_atencion = datetime.strptime(fecha_atencion, '%Y-%m-%d %H:%M')
                    except ValueError:
                        atencion.fecha_atencion = timezone.now()
            else:
                atencion.fecha_atencion = timezone.now()
            
            atencion.tipo_atencion = data.get('tipo_atencion', 'PRIMERA_VEZ')
            atencion.motivo_consulta = data.get('motivo_consulta', '')
            atencion.enfermedad_actual = data.get('enfermedad_actual', '')
            
            # Signos vitales - convertir vacíos a None
            atencion.presion_sistolica = data.get('presion_sistolica') or None
            atencion.presion_diastolica = data.get('presion_diastolica') or None
            
            temp = data.get('temperatura')
            atencion.temperatura = float(temp) if temp and temp.strip() else None

            fr = data.get('frecuencia_respiratoria')
            atencion.frecuencia_respiratoria = int(fr) if fr and fr.strip() else None

            fc = data.get('frecuencia_cardiaca')
            atencion.frecuencia_cardiaca = int(fc) if fc and fc.strip() else None

            so2 = data.get('saturacion_oxigeno')
            atencion.saturacion_oxigeno = int(so2) if so2 and so2.strip() else None

            peso = data.get('peso')
            atencion.peso = float(peso) if peso and peso.strip() else None

            talla = data.get('talla')
            atencion.talla = float(talla) if talla and talla.strip() else None

            # Calcular IMC
            if peso and talla and peso.strip() and talla.strip():
                try:
                    peso_float = float(peso)
                    talla_float = float(talla)
                    
                    if peso_float > 0 and talla_float > 0:
                        talla_metros = talla_float / 100
                        imc_val = peso_float / (talla_metros ** 2)
                        atencion.imc = round(imc_val, 2)
                    else:
                        atencion.imc = None
                except (ValueError, TypeError):
                    atencion.imc = None
            else:
                atencion.imc = None
            
            # Examen físico
            atencion.organos_sentidos = data.get('organos_sentidos') or None
            atencion.respiratorio = data.get('respiratorio') or None
            atencion.cardiovascular = data.get('cardiovascular') or None
            atencion.digestivo = data.get('digestivo') or None
            
            # Diagnóstico CIE-10
            atencion.cie10_codigo = data.get('cie10_codigo') or None
            atencion.cie10_descripcion = data.get('cie10_descripcion') or None
            atencion.diagnostico_observaciones = data.get('diagnostico_observaciones') or None
            
            # Plan y tratamiento
            atencion.plan_tratamiento = data.get('plan_tratamiento') or None
            atencion.tratamiento_no_farmacologico = data.get('tratamiento_no_farmacologico') or None
            atencion.evolucion = data.get('evolucion') or None
            
            atencion.save()
            
            return JsonResponse({
                'success': True,
                'message': 'Atención médica guardada exitosamente',
                'id_atencion': atencion.id_atencion
            })
            
    except Exception as e:
        print(f"ERROR en guardar_atencion: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# AJAX: Detalles
@login_required
def detalle_atencion(request, id):
    try:
        atencion = AtencionMedica.objects.select_related(
            'id_historia', 'id_paciente', 'id_doctor'
        ).get(id_atencion=id)
        
        # Calcular IMC si no está calculado
        if not atencion.imc and atencion.peso and atencion.talla and atencion.talla > 0:
            talla_metros = atencion.talla / 100
            atencion.imc = atencion.peso / (talla_metros * talla_metros)
        
        datos = {
            'id_atencion': atencion.id_atencion,
            'expediente': atencion.id_historia.expediente_no,
            'paciente': atencion.id_historia.nombres_completos or f"{atencion.id_paciente.first_name} {atencion.id_paciente.last_name}",
            'cedula': atencion.id_historia.cedula or 'No registrada',
            'edad': atencion.get_edad_paciente_en_atencion(),
            'sexo': atencion.id_historia.sexo_biologico,
            'doctor': f"{atencion.id_doctor.first_name} {atencion.id_doctor.last_name}",
            'fecha_atencion': atencion.fecha_atencion.strftime('%d/%m/%Y %H:%M'),
            'tipo_atencion': atencion.get_tipo_atencion_display(),
            
            # Signos vitales
            'presion_arterial': f"{atencion.presion_sistolica or ''}/{atencion.presion_diastolica or ''} {atencion.presion_media or ''}",
            'temperatura': f"{atencion.temperatura or ''} °C",
            'frecuencia_respiratoria': f"{atencion.frecuencia_respiratoria or ''} rpm",
            'frecuencia_cardiaca': f"{atencion.frecuencia_cardiaca or ''} lpm",
            'saturacion_oxigeno': f"{atencion.saturacion_oxigeno or ''}%",
            'peso': f"{atencion.peso or ''} kg",
            'talla': f"{atencion.talla or ''} cm",
            'imc': f"{atencion.imc or ''}",
            'glucosa_capilar': f"{atencion.glucosa_capilar or ''} mg/dL",
            'hemoglobina': f"{atencion.hemoglobina or ''} g/dL",
            
            # Motivos
            'motivo_consulta': atencion.motivo_consulta or 'No registrado',
            'enfermedad_actual': atencion.enfermedad_actual or 'No registrada',
            
            # Sistemas
            'organos_sentidos': atencion.organos_sentidos or 'Normal',
            'respiratorio': atencion.respiratorio or 'Normal',
            'cardiovascular': atencion.cardiovascular or 'Normal',
            'digestivo': atencion.digestivo or 'Normal',
            'genital': atencion.genital or 'Normal',
            'urinario': atencion.urinario or 'Normal',
            'esqueletico': atencion.esqueletico or 'Normal',
            'muscular': atencion.muscular or 'Normal',
            'nervioso': atencion.nervioso or 'Normal',
            'endocrino': atencion.endocrino or 'Normal',
            'hemo_linfatico': atencion.hemo_linfatico or 'Normal',
            'tegumentario': atencion.tegumentario or 'Normal',
            
            # Examenes
            'examen_frontal': atencion.examen_frontal or 'Sin hallazgos',
            'examen_posterior': atencion.examen_posterior or 'Sin hallazgos',
            'examen_general': atencion.examen_general or 'Sin hallazgos',
            'examen_neurologico': atencion.examen_neurologico or 'Sin hallazgos',
            
            # Resultados
            'resultado_laboratorio': atencion.resultado_laboratorio or 'No realizado',
            'resultado_imagenologia': atencion.resultado_imagenologia or 'No realizado',
            'resultado_histopatologia': atencion.resultado_histopatologia or 'No realizado',
            
            # Diagnóstico
            'cie10': f"{atencion.cie10_codigo or ''} - {atencion.cie10_descripcion or ''}",
            'diagnostico_observaciones': atencion.diagnostico_observaciones or 'Sin observaciones',
            'diagnostico_condicion': atencion.get_diagnostico_condicion_display() or 'No especificado',
            'diagnostico_cronologia': atencion.get_diagnostico_cronologia_display() or 'No especificado',
            
            # Plan
            'plan_tratamiento': atencion.plan_tratamiento or 'No establecido',
            'tratamiento_no_farmacologico': atencion.tratamiento_no_farmacologico or 'No aplica',
            'evolucion': atencion.evolucion or 'No registrada',
            'pronostico': atencion.pronostico or 'No establecido',
            
            # Auditoría
            'creado_por': atencion.creado_por.get_full_name() or atencion.creado_por.username,
            'fecha_creacion': atencion.fecha_creacion.strftime('%d/%m/%Y %H:%M'),
            'actualizado_por': atencion.actualizado_por.get_full_name() if atencion.actualizado_por else None,
            'fecha_actualizacion': atencion.fecha_actualizacion.strftime('%d/%m/%Y %H:%M') if atencion.actualizado_por else None,
        }
        
        return JsonResponse({'data': datos})
        
    except AtencionMedica.DoesNotExist:
        return JsonResponse({'error': 'Atención no encontrada'}, status=404)
    except Exception as e:
        print(f"ERROR en detalle_atencion: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)

# AJAX: Eliminar
@login_required
def eliminar_atencion(request):
    try:
        data = json.loads(request.body)
        atencion_id = data.get('id')
        
        atencion = AtencionMedica.objects.get(id_atencion=atencion_id)
        atencion.delete()
        
        return JsonResponse({'success': True, 'message': 'Atención eliminada'})
        
    except Exception as e:
        print(f"ERROR en eliminar_atencion: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

# AJAX: Buscar historias clínicas para atención
@login_required
def buscar_historias_atencion(request):
    try:
        query = request.GET.get('q', '').strip()
        
        if len(query) < 2:
            return JsonResponse({'data': []})
        
        historias = HistoriaClinica.objects.select_related('id_paciente').filter(
            Q(expediente_no__icontains=query) |
            Q(nombres_completos__icontains=query) |
            Q(cedula__icontains=query) |
            Q(id_paciente__first_name__icontains=query) |
            Q(id_paciente__last_name__icontains=query)
        )[:10]
        
        data = []
        for historia in historias:
            # Calcular edad
            edad = historia.get_edad_actual()
            
            data.append({
                'id_historia': historia.id_historia,
                'expediente': historia.expediente_no,
                'paciente': historia.nombres_completos or f"{historia.id_paciente.first_name} {historia.id_paciente.last_name}",
                'cedula': historia.cedula or 'Sin cédula',
                'edad': str(edad) if edad else 'N/D',
                'sexo': historia.sexo_biologico,
                'telefono': historia.telefono or 'Sin teléfono',
            })
        
        return JsonResponse({'data': data})
        
    except Exception as e:
        import traceback
        print(f"Error en buscar_historias_atencion: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'data': []})

# AJAX: Buscar CIE-10
@login_required
def buscar_cie10_atencion(request):
    try:
        query = request.GET.get('q', '').strip()
        
        if len(query) < 2:
            return JsonResponse({'data': []})
        
        cie10_list = Cie10.objects.filter(
            Q(codigo__icontains=query) |
            Q(descripcion__icontains=query)
        )[:10]
        
        data = []
        for cie in cie10_list:
            data.append({
                'codigo': cie.codigo,
                'descripcion': cie.descripcion,
            })
        
        return JsonResponse({'data': data})
        
    except Exception as e:
        import traceback
        print(f"Error en buscar_cie10_atencion: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'data': []})

# AJAX: Obtener últimos signos vitales de un paciente
@login_required
def obtener_ultimos_signos(request):
    try:
        historia_id = request.GET.get('historia_id', '')
        
        if not historia_id:
            return JsonResponse({'success': False, 'error': 'ID de historia requerido'})
        
        historia = HistoriaClinica.objects.get(id_historia=historia_id)
        
        try:
            perfil_usuario = PerfilUsuario.objects.get(user=historia.id_paciente)
            ultimos_signos = SignosVitales.objects.filter(
                perfil_usuario=perfil_usuario
            ).order_by('-fecha_registro').first()
            
            if ultimos_signos:
                # Extraer presión arterial
                
                
                datos_signos = {
                    'presion_sistolica': ultimos_signos.presion_sistolica or '',
                    'presion_diastolica': ultimos_signos.presion_diastolica or '',
                    'presion_media': str(ultimos_signos.pa_media or ''),
                    'temperatura': str(ultimos_signos.temperatura or ''),
                    'frecuencia_respiratoria': ultimos_signos.frecuencia_respiratoria or '',
                    'frecuencia_cardiaca': ultimos_signos.frecuencia_cardiaca or '',
                    'saturacion_oxigeno': ultimos_signos.saturacion_oxigeno or '',
                    'peso': str(ultimos_signos.peso or ''),
                    'talla': str(ultimos_signos.talla or ''),
                    'imc': str(ultimos_signos.imc or ''),
                    'glucosa_capilar': str(ultimos_signos.glucosa_capilar or ''),
                    'hemoglobina': str(ultimos_signos.hemoglobina or ''),
                    'fecha_registro': ultimos_signos.fecha_registro.strftime('%d/%m/%Y %H:%M')
                }

                
                return JsonResponse({
                    'success': True,
                    'signos': datos_signos
                })
            else:
                return JsonResponse({
                    'success': False,
                    'mensaje': 'No se encontraron signos vitales previos'
                })
                
        except PerfilUsuario.DoesNotExist:
            return JsonResponse({
                'success': False,
                'mensaje': 'El paciente no tiene perfil de usuario'
            })
            
    except HistoriaClinica.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Historia clínica no encontrada'})
    except Exception as e:
        print(f"ERROR en obtener_ultimos_signos: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return JsonResponse({'success': False, 'error': str(e)})
#==========================================
#certificado MEDICO
#==========================================
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User
from .models import CertificadoMedico
try:
    from .models import AtencionMedica
except ImportError:
    try:
        from atencion.models import AtencionMedica  # Ajusta según tu app
    except ImportError:
        AtencionMedica = None


@login_required
def inicio_certificado(request):
    """Vista principal de certificados médicos"""
    return render(request, 'certificado/inicio_certificado.html')


@login_required
def certificado_listado(request):
    """Listado de certificados (AJAX)"""
    try:
        q = request.GET.get('q', '').strip()
        certificados = CertificadoMedico.objects.select_related(
            'id_paciente', 'id_doctor', 'id_atencion'
        ).all()
        
        if q:
            certificados = certificados.filter(
                models.Q(id_paciente__first_name__icontains=q) |
                models.Q(id_paciente__last_name__icontains=q) |
                models.Q(id_paciente__username__icontains=q) |
                models.Q(id_doctor__first_name__icontains=q) |
                models.Q(id_doctor__last_name__icontains=q) |
                models.Q(tipo_certificado__icontains=q) |
                models.Q(motivo__icontains=q) |
                models.Q(diagnostico__icontains=q)
            )
        
        data = []
        for cert in certificados:
            data.append({
                'id_certificado': cert.id_certificado,
                'codigo': cert.get_codigo_certificado(),
                'paciente': cert.get_paciente_nombre(),
                'doctor': cert.get_doctor_nombre(),
                'tipo_certificado': cert.get_tipo_certificado_display(),
                'fecha_emision': cert.fecha_emision.strftime('%d/%m/%Y'),
                'estado': cert.estado,
                'dias_reposo': cert.dias_reposo if cert.dias_reposo else '-',
            })
        
        return JsonResponse({'data': data})
    except Exception as e:
        print(f"Error en certificado_listado: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def certificado_formulario(request):
    """Cargar formulario para nuevo o editar certificado"""
    try:
        cert_id = request.GET.get('id')
        certificado = None
        
        if cert_id:
            certificado = get_object_or_404(CertificadoMedico, id_certificado=cert_id)
        
        # Obtener atenciones
        atenciones_list = []
        if AtencionMedica is not None:
            try:
                atenciones = AtencionMedica.objects.all().order_by('-fecha_atencion')[:100]
                for a in atenciones:
                    atenciones_list.append({
                        'id_atencion': a.id_atencion,
                        'fecha_atencion': a.fecha_atencion.strftime('%d/%m/%Y')
                    })
            except Exception as e:
                print(f"Error al cargar atenciones: {str(e)}")
        
        # Obtener pacientes
        try:
            pacientes = User.objects.filter(groups__name='Paciente').order_by('first_name', 'last_name')
            if not pacientes.exists():
                pacientes = User.objects.filter(is_active=True).order_by('first_name', 'last_name')
        except Exception as e:
            print(f"Error al cargar pacientes: {str(e)}")
            pacientes = User.objects.filter(is_active=True).order_by('first_name', 'last_name')
        
        pacientes_list = []
        for p in pacientes:
            pacientes_list.append({
                'id': p.id,
                'first_name': p.first_name or '',
                'last_name': p.last_name or '',
                'username': p.username or ''
            })
        
        # Obtener doctores
        try:
            doctores = User.objects.filter(groups__name='Doctor').order_by('first_name', 'last_name')
            if not doctores.exists():
                doctores = User.objects.filter(is_staff=True, is_active=True).order_by('first_name', 'last_name')
        except Exception as e:
            print(f"Error al cargar doctores: {str(e)}")
            doctores = User.objects.filter(is_staff=True, is_active=True).order_by('first_name', 'last_name')
        
        doctores_list = []
        for d in doctores:
            doctores_list.append({
                'id': d.id,
                'first_name': d.first_name or '',
                'last_name': d.last_name or ''
            })
        
        import json
        
        form_html = render_to_string(
            'certificado/formulario_certificado.html',
            {
                'item': certificado,
                'atenciones': json.dumps(atenciones_list),
                'pacientes': json.dumps(pacientes_list),
                'doctores': json.dumps(doctores_list),
            },
            request=request
        )
        
        return JsonResponse({'form_html': form_html})
    except Exception as e:
        print(f"Error en certificado_formulario: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def certificado_guardar(request):
    """Guardar certificado médico"""
    try:
        cert_id = request.POST.get('id_certificado')
        
        if cert_id:
            certificado = get_object_or_404(CertificadoMedico, id_certificado=cert_id)
            es_nuevo = False
        else:
            certificado = CertificadoMedico()
            certificado.creado_por = request.user
            es_nuevo = True
        
        # Validar campos requeridos
        if not request.POST.get('id_paciente'):
            return JsonResponse({'success': False, 'error': 'Debe seleccionar un paciente'}, status=400)
        
        if not request.POST.get('id_doctor'):
            return JsonResponse({'success': False, 'error': 'Debe seleccionar un doctor'}, status=400)
        
        # ✅ CORRECCIÓN: Asignar id_atencion correctamente
        atencion_id = request.POST.get('id_atencion', '').strip()
        if atencion_id and atencion_id != '':
            certificado.id_atencion_id = atencion_id
        else:
            certificado.id_atencion_id = None  # ✅ Usar _id en lugar de solo el campo
        
        certificado.id_paciente_id = request.POST.get('id_paciente')
        certificado.id_doctor_id = request.POST.get('id_doctor')
        certificado.fecha_emision = request.POST.get('fecha_emision')
        certificado.hora_emision = request.POST.get('hora_emision')
        certificado.tipo_certificado = request.POST.get('tipo_certificado')
        certificado.motivo = request.POST.get('motivo')
        certificado.diagnostico = request.POST.get('diagnostico', '')
        
        # Guardar días de reposo
        dias_reposo = request.POST.get('dias_reposo', '').strip()
        certificado.dias_reposo = int(dias_reposo) if dias_reposo else None
        
        # ✅ Manejar fechas vacías correctamente
        fecha_inicio = request.POST.get('fecha_inicio_reposo', '').strip()
        fecha_fin = request.POST.get('fecha_fin_reposo', '').strip()
        
        certificado.fecha_inicio_reposo = fecha_inicio if fecha_inicio else None
        certificado.fecha_fin_reposo = fecha_fin if fecha_fin else None
        certificado.indicaciones = request.POST.get('indicaciones', '')
        certificado.observaciones = request.POST.get('observaciones', '')
        
        certificado.save()
        
        mensaje = 'Certificado creado exitosamente' if es_nuevo else 'Certificado actualizado exitosamente'
        return JsonResponse({'success': True, 'message': mensaje})
        
    except Exception as e:
        print(f"Error en certificado_guardar: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

@login_required
@require_http_methods(["POST"])
def certificado_eliminar(request):
    """Eliminar (anular) certificado médico"""
    try:
        cert_id = request.POST.get('id')
        certificado = get_object_or_404(CertificadoMedico, id_certificado=cert_id)
        
        # Anular en lugar de eliminar
        certificado.anular(request.user, 'Eliminado por usuario')
        
        return JsonResponse({
            'success': True,
            'message': 'Certificado anulado exitosamente'
        })
    except Exception as e:
        print(f"Error en certificado_eliminar: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def certificado_reactivar(request):
    """Reactivar certificado anulado"""
    try:
        print(f"DEBUG - Reactivar - POST data: {request.POST}")
        print(f"DEBUG - Reactivar - CSRF Token: {request.META.get('HTTP_X_CSRFTOKEN', 'NO TOKEN')}")
        
        cert_id = request.POST.get('id')
        if not cert_id:
            return JsonResponse({
                'success': False, 
                'error': 'ID de certificado no proporcionado'
            }, status=400)
        
        certificado = get_object_or_404(CertificadoMedico, id_certificado=cert_id)
        
        if certificado.estado != 'ANULADO':
            return JsonResponse({
                'success': False, 
                'error': 'El certificado ya está activo'
            }, status=400)
        
        # Reactivar certificado
        certificado.estado = 'ACTIVO'
        timestamp = timezone.now().strftime('%d/%m/%Y %H:%M')
        usuario_nombre = request.user.get_full_name() or request.user.username
        certificado.observaciones = f"{certificado.observaciones or ''}\n\nREACTIVADO: Por {usuario_nombre} ({timestamp})"
        certificado.save()
        
        print(f"DEBUG - Certificado {cert_id} reactivado exitosamente")
        
        return JsonResponse({
            'success': True,
            'message': 'Certificado reactivado exitosamente'
        })
    except Exception as e:
        print(f"Error en certificado_reactivar: {str(e)}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=400)


@login_required
def imprimir_certificado(request, id):
    """Vista para imprimir certificado"""
    certificado = get_object_or_404(
        CertificadoMedico.objects.select_related(
            'id_paciente', 'id_doctor', 'id_atencion'
        ),
        id_certificado=id
    )
    
    return render(request, 'certificado/imprimir_certificado.html', {
        'certificado': certificado
    })


# ============================================================================
# VISTA PRINCIPAL
# ============================================================================

@login_required
def inicio_receta(request):
    """Vista principal del módulo de recetas médicas"""
    return render(request, 'receta/inicio_receta.html')


# ============================================================================
# OBTENER HISTORIAS CLÍNICAS
# ============================================================================

@login_required
def obtener_historias(request):
    """
    Obtiene las historias clínicas que tienen atenciones del doctor actual.
    """
    try:
        # Buscar historias que tienen atenciones del doctor actual
        historias = HistoriaClinica.objects.filter(
            atenciones__id_doctor=request.user.id
        ).distinct().select_related('id_paciente')
        
        data = []
        for historia in historias:
            # Obtener nombre del paciente
            paciente_nombre = ""
            if hasattr(historia, 'nombres_completos') and historia.nombres_completos:
                paciente_nombre = historia.nombres_completos
            elif historia.id_paciente:
                paciente_nombre = f"{historia.id_paciente.first_name or ''} {historia.id_paciente.last_name or ''}".strip()
                if not paciente_nombre:
                    paciente_nombre = historia.id_paciente.username
            
            # Contar atenciones del doctor con esta historia
            total_atenciones = AtencionMedica.objects.filter(
                id_historia=historia,
                id_doctor=request.user
            ).count()
            
            data.append({
                'id_historia': historia.id_historia,
                'expediente_no': historia.expediente_no or 'Sin expediente',
                'paciente_nombre': paciente_nombre or 'Sin nombre',
                'cedula': getattr(historia, 'cedula', 'Sin cédula'),
                'total_atenciones': total_atenciones
            })
        
        return JsonResponse({
            'success': True,
            'data': data
        })
        
    except Exception as e:
        print(f"❌ ERROR en obtener_historias: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': str(e),
            'data': []
        }, status=500)


# ============================================================================
# LISTADO DE RECETAS (CORREGIDO - NO usa select_related con id_paciente_user)
# ============================================================================

@login_required
def listado_recetas(request):
    """
    Obtiene el listado de recetas con filtros opcionales.
    """
    try:
        historia_id = request.GET.get('historia_id', '')
        
        # Filtrar recetas del doctor actual - SIN select_related incorrecto
        recetas = Receta.objects.filter(
            id_doctor=request.user.id
        ).prefetch_related('detalles').order_by('-fecha_emision')
        
        # Filtrar por historia si se especifica
        if historia_id and historia_id != '':
            # Obtener IDs de atenciones de esa historia para este doctor
            atenciones_ids = AtencionMedica.objects.filter(
                id_historia_id=historia_id,
                id_doctor=request.user
            ).values_list('id_atencion', flat=True)
            
            recetas = recetas.filter(id_atencion__in=atenciones_ids)
        
        data = []
        for receta in recetas:
            try:
                # Obtener la atención asociada
                atencion = AtencionMedica.objects.select_related('id_historia').get(id_atencion=receta.id_atencion)
                historia = atencion.id_historia
                
                # Obtener el objeto User del paciente
                try:
                    paciente_user = User.objects.get(id=receta.id_paciente)
                    paciente_nombre = f"{paciente_user.first_name or ''} {paciente_user.last_name or ''}".strip()
                    if not paciente_nombre:
                        paciente_nombre = paciente_user.username
                except User.DoesNotExist:
                    paciente_nombre = "Paciente no encontrado"
                
                # Verificar si hay un nombre en la historia
                if hasattr(historia, 'nombres_completos') and historia.nombres_completos:
                    paciente_nombre = historia.nombres_completos
                
                data.append({
                    'id_receta': receta.id_receta,
                    'expediente_no': historia.expediente_no or 'Sin expediente',
                    'paciente_nombre': paciente_nombre or 'Sin nombre',
                    'fecha': receta.fecha_emision.strftime('%d/%m/%Y %H:%M') if receta.fecha_emision else '',
                    'motivo': receta.motivo or 'Sin motivo',
                    'cantidad_medicamentos': receta.detalles.count(),
                    'estado': receta.estado,
                    'estado_display': receta.get_estado_display(),
                    'puede_editar': receta.estado == 'ACTIVA',
                    'puede_anular': receta.estado == 'ACTIVA',
                    'puede_eliminar': receta.estado == 'ACTIVA',
                })
            except AtencionMedica.DoesNotExist:
                print(f"⚠️ Atención no encontrada para receta {receta.id_receta}")
                continue
            except Exception as e:
                print(f"⚠️ Error procesando receta {receta.id_receta}: {str(e)}")
                continue
        
        return JsonResponse({
            'success': True,
            'data': data
        })
        
    except Exception as e:
        print(f"❌ ERROR en listado_recetas: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'data': [],
            'error': str(e)
        }, status=500)


# ============================================================================
# OBTENER FORMULARIO DE RECETA
# ============================================================================

@login_required
def obtener_formulario_receta(request):
    """
    Carga el formulario de receta (nuevo o edición).
    """
    try:
        receta_id = request.GET.get('receta_id', '')
        historia_id = request.GET.get('historia_id', '')
        
        print(f"🔍 obtener_formulario_receta - receta_id: {receta_id}, historia_id: {historia_id}")
        
        receta = None
        historia = None
        paciente_nombre = ''
        expediente_no = ''
        paciente_id = None
        
        # ===== MODO EDICIÓN =====
        if receta_id:
            # Obtener receta con sus detalles
            receta = get_object_or_404(
                Receta.objects.prefetch_related('detalles'),
                id_receta=receta_id,
                id_doctor=request.user.id
            )
            
            # Obtener atención y datos relacionados
            atencion = get_object_or_404(
                AtencionMedica.objects.select_related('id_historia'),
                id_atencion=receta.id_atencion
            )
            
            historia = atencion.id_historia
            paciente_id = receta.id_paciente  # ID del paciente desde la receta
            
            # Obtener nombre del paciente
            try:
                paciente_user = User.objects.get(id=paciente_id)
                paciente_nombre = f"{paciente_user.first_name or ''} {paciente_user.last_name or ''}".strip()
                if not paciente_nombre:
                    paciente_nombre = paciente_user.username
            except User.DoesNotExist:
                paciente_nombre = "Paciente no encontrado"
            
            # Verificar si hay un nombre en la historia
            if hasattr(historia, 'nombres_completos') and historia.nombres_completos:
                paciente_nombre = historia.nombres_completos
            
            expediente_no = historia.expediente_no or 'Sin expediente'
            
        # ===== MODO NUEVA RECETA =====
        elif historia_id:
            # Obtener historia clínica
            historia = get_object_or_404(
                HistoriaClinica.objects.select_related('id_paciente'),
                id_historia=historia_id
            )
            
            # Verificar que el doctor tenga al menos una atención con esta historia
            tiene_atencion = AtencionMedica.objects.filter(
                id_historia=historia,
                id_doctor=request.user
            ).exists()
            
            if not tiene_atencion:
                return JsonResponse({
                    'success': False,
                    'error': 'No tiene atenciones registradas con este paciente'
                }, status=403)
            
            paciente_id = historia.id_paciente_id
            
            # Obtener datos del paciente
            if hasattr(historia, 'nombres_completos') and historia.nombres_completos:
                paciente_nombre = historia.nombres_completos
            elif historia.id_paciente:
                paciente = historia.id_paciente
                paciente_nombre = f"{paciente.first_name or ''} {paciente.last_name or ''}".strip()
                if not paciente_nombre:
                    paciente_nombre = paciente.username
            
            expediente_no = historia.expediente_no or 'Sin expediente'
            
        else:
            return JsonResponse({
                'success': False,
                'error': 'Debe especificar historia_id o receta_id'
            }, status=400)
        
        # Renderizar formulario
        context = {
            'receta': receta,
            'historia': historia,
            'paciente_nombre': paciente_nombre,
            'expediente_no': expediente_no,
            'paciente_id': paciente_id,
        }
        
        form_html = render_to_string(
            'receta/formulario_receta.html',
            context,
            request=request
        )
        
        return JsonResponse({
            'success': True,
            'form_html': form_html
        })
        
    except Exception as e:
        print(f"❌ ERROR en obtener_formulario_receta: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': f'Error al cargar formulario: {str(e)}'
        }, status=500)


# ============================================================================
# GUARDAR RECETA (CORREGIDO)
# ============================================================================

@login_required
@transaction.atomic
def guardar_receta(request):
    """
    Guarda o actualiza una receta médica.
    """
    try:
        # Parsear datos JSON
        data = json.loads(request.body)
        print(f"📥 Datos recibidos para guardar: {data}")
        
        receta_id = data.get('id_receta', '').strip()
        historia_id = data.get('id_historia')
        motivo = data.get('motivo', '').strip()
        observaciones = data.get('observaciones', '').strip()
        detalles = data.get('detalles', [])
        
        # ===== VALIDACIONES =====
        if not historia_id:
            return JsonResponse({
                'success': False,
                'error': 'Historia clínica requerida'
            }, status=400)
        
        if not motivo:
            return JsonResponse({
                'success': False,
                'error': 'Motivo de la receta requerido'
            }, status=400)
        
        if not detalles or len(detalles) == 0:
            return JsonResponse({
                'success': False,
                'error': 'Debe agregar al menos un medicamento'
            }, status=400)
        
        with transaction.atomic():
            
            # ===== MODO EDICIÓN =====
            if receta_id:
                receta = get_object_or_404(
                    Receta,
                    id_receta=receta_id,
                    id_doctor=request.user.id
                )
                
                if receta.estado != 'ACTIVA':
                    return JsonResponse({
                        'success': False,
                        'error': 'No se puede editar una receta que no está activa'
                    }, status=400)
                
                # Eliminar detalles existentes
                RecetaDetalle.objects.filter(id_receta=receta).delete()
                
                # Actualizar datos básicos
                receta.motivo = motivo
                receta.observaciones = observaciones
                receta.actualizado_por = request.user.id
                receta.fecha_actualizacion = timezone.now()
                receta.save()
                
                print(f"✅ Receta actualizada: {receta.id_receta}")
                modo = "actualizada"
            
            # ===== MODO NUEVA RECETA =====
            else:
                # Obtener historia clínica
                historia = get_object_or_404(
                    HistoriaClinica.objects.select_related('id_paciente'),
                    id_historia=historia_id
                )
                
                # Buscar la última atención del doctor con esta historia
                ultima_atencion = AtencionMedica.objects.filter(
                    id_historia=historia,
                    id_doctor=request.user
                ).order_by('-fecha_atencion').first()

                # Si no existe atención, crear una nueva
                if not ultima_atencion:
                    ultima_atencion = AtencionMedica.objects.create(
                        id_historia=historia,
                        id_paciente=historia.id_paciente,
                        id_doctor=request.user,
                        motivo_consulta='Atención automática para receta',
                        fecha_atencion=timezone.now(),
                        creado_por=request.user.id
                    )
                    print(f"✅ Atención creada automáticamente: {ultima_atencion.id_atencion}")
                
                # Crear nueva receta
                receta = Receta.objects.create(
                    id_atencion=ultima_atencion.id_atencion,
                    id_paciente=historia.id_paciente.id,  # ID del User paciente
                    id_doctor=request.user.id,
                    motivo=motivo,
                    indicaciones_generales='',
                    observaciones=observaciones,
                    estado='ACTIVA',
                    creado_por=request.user.id,
                    actualizado_por=request.user.id,
                    fecha_emision=timezone.now()
                )
                
                print(f"✅ Receta creada: {receta.id_receta}")
                modo = "creada"
            
            # ===== GUARDAR DETALLES =====
            for idx, detalle_data in enumerate(detalles):
                # Validar datos del detalle
                medicamento = detalle_data.get('medicamento', '').strip()
                dosis = detalle_data.get('dosis', '').strip()
                frecuencia = detalle_data.get('frecuencia', '').strip()
                duracion_dias = int(detalle_data.get('duracion_dias', 0) or 0)
                cantidad_total = int(detalle_data.get('cantidad_total', 0) or 0)
                via_administracion = detalle_data.get('via_administracion', '').strip()
                
                if not medicamento:
                    return JsonResponse({
                        'success': False,
                        'error': f'Medicamento requerido en el item {idx + 1}'
                    }, status=400)
                
                if not dosis:
                    return JsonResponse({
                        'success': False,
                        'error': f'Dosis requerida en el item {idx + 1}'
                    }, status=400)
                
                if not frecuencia:
                    return JsonResponse({
                        'success': False,
                        'error': f'Frecuencia requerida en el item {idx + 1}'
                    }, status=400)
                
                if duracion_dias <= 0:
                    return JsonResponse({
                        'success': False,
                        'error': f'Duración en días debe ser mayor a 0 en el item {idx + 1}'
                    }, status=400)
                
                if cantidad_total <= 0:
                    return JsonResponse({
                        'success': False,
                        'error': f'Cantidad total debe ser mayor a 0 en el item {idx + 1}'
                    }, status=400)
                
                if not via_administracion:
                    return JsonResponse({
                        'success': False,
                        'error': f'Vía de administración requerida en el item {idx + 1}'
                    }, status=400)
                
                # Crear detalle
                RecetaDetalle.objects.create(
                    id_receta=receta,
                    medicamento=medicamento,
                    concentracion=detalle_data.get('concentracion', '').strip(),
                    presentacion=detalle_data.get('presentacion', '').strip(),
                    dosis=dosis,
                    frecuencia=frecuencia,
                    duracion_dias=duracion_dias,
                    cantidad_total=cantidad_total,
                    via_administracion=via_administracion,
                    indicaciones=detalle_data.get('indicaciones', '').strip(),
                    advertencias=detalle_data.get('advertencias', '').strip(),
                    orden=idx
                )
                print(f"  ✅ Detalle {idx + 1}: {medicamento}")
            
            return JsonResponse({
                'success': True,
                'message': f'Receta {modo} exitosamente',
                'id_receta': receta.id_receta
            })
        
    except json.JSONDecodeError as e:
        print(f"❌ Error JSON: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"❌ ERROR en guardar_receta: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': f'Error al guardar: {str(e)}'
        }, status=500)


# ============================================================================
# VER DETALLE DE RECETA
# ============================================================================

@login_required
def detalle_receta(request, id):
    """
    Obtiene los detalles completos de una receta.
    """
    try:
        # Obtener receta con sus detalles
        receta = get_object_or_404(
            Receta.objects.prefetch_related('detalles'),
            id_receta=id,
            id_doctor=request.user.id
        )
        
        # Obtener atención y datos relacionados
        atencion = AtencionMedica.objects.select_related('id_historia').get(id_atencion=receta.id_atencion)
        historia = atencion.id_historia
        
        # Obtener doctor y paciente
        doctor = User.objects.get(id=receta.id_doctor)
        
        # Obtener nombre del paciente
        try:
            paciente_user = User.objects.get(id=receta.id_paciente)
            paciente_nombre = f"{paciente_user.first_name or ''} {paciente_user.last_name or ''}".strip()
            if not paciente_nombre:
                paciente_nombre = paciente_user.username
        except User.DoesNotExist:
            paciente_nombre = "Paciente no encontrado"
        
        # Verificar si hay un nombre en la historia
        if hasattr(historia, 'nombres_completos') and historia.nombres_completos:
            paciente_nombre = historia.nombres_completos
        
        # Preparar lista de detalles
        detalles_list = []
        for detalle in receta.detalles.all().order_by('orden'):
            detalles_list.append({
                'medicamento': detalle.medicamento,
                'concentracion': detalle.concentracion or '',
                'presentacion': detalle.presentacion or '',
                'dosis': detalle.dosis,
                'frecuencia': detalle.frecuencia,
                'duracion_dias': detalle.duracion_dias,
                'cantidad_total': detalle.cantidad_total,
                'via_administracion': detalle.via_administracion,
                'indicaciones': detalle.indicaciones or '',
                'advertencias': detalle.advertencias or '',
            })
        
        # Preparar respuesta
        data = {
            'id_receta': receta.id_receta,
            'expediente_no': historia.expediente_no or 'Sin expediente',
            'paciente_nombre': paciente_nombre or 'Sin nombre',
            'cedula': getattr(historia, 'cedula', 'Sin cédula'),
            'doctor_nombre': f"{doctor.first_name or ''} {doctor.last_name or ''}".strip() or doctor.username,
            'fecha': receta.fecha_emision.strftime('%d/%m/%Y %H:%M') if receta.fecha_emision else '',
            'motivo': receta.motivo or '',
            'observaciones': receta.observaciones or '',
            'estado': receta.estado,
            'estado_display': receta.get_estado_display(),
            'detalles': detalles_list,
        }
        
        return JsonResponse({
            'success': True,
            'data': data
        })
        
    except Exception as e:
        print(f"❌ ERROR en detalle_receta: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# ============================================================================
# ANULAR RECETA
# ============================================================================

@login_required
@transaction.atomic
def anular_receta(request):
    """
    Anula una receta activa (cambia estado a ANULADA).
    """
    try:
        data = json.loads(request.body)
        receta_id = data.get('id_receta')
        
        if not receta_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de receta requerido'
            }, status=400)
        
        receta = get_object_or_404(
            Receta,
            id_receta=receta_id,
            id_doctor=request.user.id
        )
        
        if receta.estado != 'ACTIVA':
            return JsonResponse({
                'success': False,
                'error': 'Solo se pueden anular recetas activas'
            }, status=400)
        
        receta.estado = 'ANULADA'
        receta.actualizado_por = request.user.id
        receta.fecha_actualizacion = timezone.now()
        receta.save()
        
        print(f"✅ Receta {receta_id} anulada exitosamente")
        
        return JsonResponse({
            'success': True,
            'message': 'Receta anulada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"❌ ERROR en anular_receta: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# ============================================================================
# ELIMINAR RECETA
# ============================================================================

@login_required
@transaction.atomic
def eliminar_receta(request):
    """
    Elimina permanentemente una receta activa.
    """
    try:
        data = json.loads(request.body)
        receta_id = data.get('id_receta')
        
        if not receta_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de receta requerido'
            }, status=400)
        
        receta = get_object_or_404(
            Receta,
            id_receta=receta_id,
            id_doctor=request.user.id
        )
        
        if receta.estado != 'ACTIVA':
            return JsonResponse({
                'success': False,
                'error': 'Solo se pueden eliminar recetas activas'
            }, status=400)
        
        # Eliminar receta (los detalles se eliminan en cascada)
        receta.delete()
        
        print(f"✅ Receta {receta_id} eliminada exitosamente")
        
        return JsonResponse({
            'success': True,
            'message': 'Receta eliminada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"❌ ERROR en eliminar_receta: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
# ========== 13) REPORTES ==========
@login_required
def reportes_dashboard(request):
    """Dashboard de reportes y estadísticas"""
    from django.db.models import Count, Sum, Avg
    from django.utils import timezone
    from datetime import datetime, timedelta
    from .models import Cita, User
    
    # Filtros por fechas (últimos 30 días por defecto)
    hoy = timezone.now().date()
    hace_30_dias = hoy - timedelta(days=30)
    
    # Obtener el usuario actual y sus permisos
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    is_paciente = request.user.groups.filter(name="Paciente").exists()
    
    # Estadísticas de citas
    citas_query = Cita.objects.filter(fecha_hora__date__gte=hace_30_dias)
    
    # Filtrar según el rol
    if is_doctor:
        citas_query = citas_query.filter(id_doctor=request.user)
    elif is_paciente:
        citas_query = citas_query.filter(id_paciente=request.user)
    
    # Total de citas
    total_citas = citas_query.count()
    
    # Citas por estado
    citas_pendientes = citas_query.filter(estado="PENDIENTE").count()
    citas_atendidas = citas_query.filter(estado="ATENDIDA").count()
    citas_canceladas = citas_query.filter(estado="CANCELADA").count()
    
    # Citas por día (para el gráfico)
    citas_por_dia = citas_query.annotate(
        fecha=TruncDay('fecha_hora')
    ).values('fecha').annotate(
        total=Count('id_cita')
    ).order_by('fecha')
    
    # Datos para gráficos
    # Datos para gráficos
    datos_grafico = []
    for cita in citas_por_dia:
        datos_grafico.append({
            'fecha': cita['fecha'].strftime('%Y-%m-%d'),
            'total': cita['total']
        })

    # Separar para gráficos (mantener compatibilidad)
    fechas = [d['fecha'] for d in datos_grafico]
    totales = [d['total'] for d in datos_grafico]
        
    # Top doctores (solo para admin)
    top_doctores = []
    if is_admin:
        doctores_stats = Cita.objects.filter(
            fecha_hora__date__gte=hace_30_dias
        ).values('id_doctor__first_name', 'id_doctor__last_name').annotate(
            total_citas=Count('id_cita')
        ).order_by('-total_citas')[:5]
        
        for doc in doctores_stats:
            top_doctores.append({
                'nombre': f"{doc['id_doctor__first_name']} {doc['id_doctor__last_name']}",
                'total': doc['total_citas']
            })
    
    context = {
        'hoy': hoy,
        'hace_30_dias': hace_30_dias,
        'total_citas': total_citas,
        'citas_pendientes': citas_pendientes,
        'citas_atendidas': citas_atendidas,
        'citas_canceladas': citas_canceladas,
        'fechas': fechas,
        'totales': totales,
        'top_doctores': top_doctores,
        'is_admin': is_admin,
        'is_doctor': is_doctor,
        'is_paciente': is_paciente,
    }
    
    return render(request, "reportes/dashboard.html", context)

@login_required
def reportes_citas_ajax(request):
    """API para datos de citas en formato JSON (para gráficos AJAX)"""
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta
    from .models import Cita
    
    # Parámetros de filtro
    dias = int(request.GET.get('dias', 30))
    hoy = timezone.now().date()
    fecha_inicio = hoy - timedelta(days=dias)
    
    # Filtrar según el rol
    citas_query = Cita.objects.filter(fecha_hora__date__gte=fecha_inicio)
    
    if not request.user.groups.filter(name="Administrador").exists():
        if request.user.groups.filter(name="Doctor").exists():
            citas_query = citas_query.filter(id_doctor=request.user)
        elif request.user.groups.filter(name="Paciente").exists():
            citas_query = citas_query.filter(id_paciente=request.user)
    
    # Estadísticas
    citas_por_dia = citas_query.annotate(
        fecha=TruncDay('fecha_hora')
    ).values('fecha').annotate(
        total=Count('id_cita')
    ).order_by('fecha')
    
    # Citas por estado
    citas_por_estado = citas_query.values('estado').annotate(
        total=Count('id_cita')
    )
    
    # Citas por doctor (solo admin)
    citas_por_doctor = []
    if request.user.groups.filter(name="Administrador").exists():
        citas_por_doctor = citas_query.values(
            'id_doctor__first_name', 
            'id_doctor__last_name'
        ).annotate(
            total=Count('id_cita')
        ).order_by('-total')[:10]
    
    data = {
        'citas_por_dia': list(citas_por_dia),
        'citas_por_estado': list(citas_por_estado),
        'citas_por_doctor': list(citas_por_doctor),
        'fecha_inicio': fecha_inicio,
        'fecha_fin': hoy,
        'total_citas': citas_query.count()
    }
    
    return JsonResponse(data, safe=False)
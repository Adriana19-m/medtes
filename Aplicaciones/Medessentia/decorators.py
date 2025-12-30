from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied


def solo_admin(view_func):
    """Permite solo a superusuarios o miembros del grupo 'Administrador'."""
    def check_admin(user):
        return user.is_authenticated and (user.is_superuser or user.groups.filter(name="Administrador").exists())
    return user_passes_test(check_admin, login_url='/')(view_func)

def solo_doctor(view_func):
    """Permite solo a usuarios del grupo 'Doctor'."""
    def check_doctor(user):
        return user.is_authenticated and user.groups.filter(name="Doctor").exists()
    return user_passes_test(check_doctor, login_url='/')(view_func)

def solo_paciente(view_func):
    """Permite solo a usuarios del grupo 'Paciente'."""
    def check_paciente(user):
        return user.is_authenticated and user.groups.filter(name="Paciente").exists()
    return user_passes_test(check_paciente, login_url='/')(view_func)


def solo_admin_o_doctor(view_func):
    """Permite solo a doctores o administradores."""
    def check(user):
        return user.is_authenticated and (
            user.is_superuser
            or user.groups.filter(name__in=["Administrador", "Doctor"]).exists()
        )
    return user_passes_test(check, login_url='/')(view_func)


def propietario_o_admin(model_class):
    """
    Permite acceso si el usuario es dueño del objeto o es administrador.
    Se usa en vistas de edición/eliminación.
    """
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            obj = model_class.objects.get(pk=kwargs.get('pk') or kwargs.get('id'))
            if not (request.user.is_superuser or obj.user == request.user):
                raise PermissionDenied("No tienes permiso para acceder a este recurso.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

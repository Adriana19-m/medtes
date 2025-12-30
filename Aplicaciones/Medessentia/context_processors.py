def roles_usuario(request):
    if not request.user.is_authenticated:
        return {}

    return {
        'es_admin': request.user.groups.filter(name='Administrador').exists(),
        'es_doctor': request.user.groups.filter(name='Doctor').exists(),
        'es_paciente': request.user.groups.filter(name='Paciente').exists(),
    }

from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.conf import settings
from django.db import models
from datetime import date
from django.utils import timezone


def validar_cedula_ecuatoriana(cedula):
    if len(cedula) != 10 or not cedula.isdigit():
        raise ValidationError("La cédula debe tener 10 dígitos numéricos.")

    provincia = int(cedula[:2])
    if provincia < 1 or provincia > 24:
        raise ValidationError("La cédula debe pertenecer a una provincia válida (01-24).")

    total = 0
    for i in range(9):
        num = int(cedula[i])
        if i % 2 == 0:  
            num *= 2
            if num > 9:
                num -= 9
        total += num

    verificador = 10 - (total % 10) if total % 10 != 0 else 0
    if verificador != int(cedula[9]):
        raise ValidationError("Cédula ecuatoriana no válida.")


class PerfilUsuario(models.Model):
    GENEROS = [
        ('Masculino', 'Masculino'),
        ('Femenino', 'Femenino'),
        ('Otro', 'Otro'),
    ]
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="perfil"
    )
    genero_usuario = models.CharField(
        max_length=10, choices=GENEROS, blank=True, null=True
    )
    cedula_usuario = models.CharField(
        max_length=10, unique=True, validators=[validar_cedula_ecuatoriana]
    )

    telefono_usuario = models.CharField(
        max_length=10, blank=True, null=False, default="0000000000"
    )
    direccion_usuario = models.CharField(
        max_length=200, blank=True, default=""
    )
    fecha_registro_usuario = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "perfil_usuario"
        managed = True

    def __str__(self):
        return f"{self.user.username} - {self.cedula_usuario or 'sin cédula'}"

class SignosVitales(models.Model):
    perfil_usuario = models.ForeignKey(PerfilUsuario, on_delete=models.CASCADE, related_name='signos_vitales')
    fecha_registro = models.DateTimeField()
    presion_arterial = models.CharField(max_length=20)  
    frecuencia_cardiaca = models.IntegerField()
    frecuencia_respiratoria = models.IntegerField()
    temperatura = models.DecimalField(max_digits=4, decimal_places=1)
    saturacion_oxigeno = models.IntegerField()
    peso = models.DecimalField(max_digits=5, decimal_places=2)
    talla = models.DecimalField(max_digits=4, decimal_places=2)
    imc = models.DecimalField(max_digits=4, decimal_places=2, blank=True, null=True)
    observaciones = models.TextField(blank=True, null=True)

    pa_sistolica = models.IntegerField(blank=True, null=True)         
    pa_diastolica = models.IntegerField(blank=True, null=True)        
    pa_media = models.DecimalField(max_digits=5, decimal_places=2,    
                                   blank=True, null=True)

    glucosa_capilar = models.DecimalField(max_digits=6, decimal_places=1,
                                          blank=True, null=True)      
    hemoglobina = models.DecimalField(max_digits=4, decimal_places=1,
                                      blank=True, null=True)          

    class Meta:
        db_table = "signos_vitales"
        managed = True


ESTADO_CIVIL_CHOICES = [
    ("SOLTERO", "Soltero"),
    ("CASADO", "Casado"),
    ("DIVORCIADO", "Divorciado"),
    ("VIUDO", "Viudo"),
    ("UNION_LIBRE", "Unión libre"),
    ("OTRO", "Otro"),
]

GRUPO_SANGUINEO_CHOICES = [
    ("A+", "A+"), ("A-", "A-"),
    ("B+", "B+"), ("B-", "B-"),
    ("AB+", "AB+"), ("AB-", "AB-"),
    ("O+", "O+"), ("O-", "O-"),
    ("DESCONOCIDO", "Desconocido"),
]

TIPO_DIAG_CHOICES = [
    ("PRINCIPAL", "Principal"),
    ("SECUNDARIO", "Secundario"),
    ("PRESUNTIVO", "Presuntivo"),
    ("DEFINITIVO", "Definitivo"),
]

CONDICION_CHOICES = [
    ("PRESUNTIVO", "Presuntivo"),
    ("DEFINITIVO_INICIAL", "Definitivo inicial"),
    ("DEFINITIVO_CONFIRMADO_LAB", "Definitivo confirmado lab"),
    ("DEFINITIVO_CONTROL", "Definitivo control"),
]

CRONOLOGIA_CHOICES = [
    ("PRIMERA", "Primera"),
    ("SUBSECUENTE", "Subsecuente"),
]

TIPO_CITA_CHOICES = [
    ("PRESENCIAL", "Presencial"),
    ("TELECONSULTA", "Teleconsulta"),
    ("DOMICILIO", "Domicilio"),
    ("OTRO", "Otro"),
]

ESTADO_CITA_CHOICES = [
    ("PENDIENTE", "Pendiente"),
    ("CONFIRMADA", "Confirmada"),
    ("ATENDIDA", "Atendida"),
    ("CANCELADA", "Cancelada"),
    ("NO_ASISTE", "No asiste"),
    ("REPROGRAMADA", "Reprogramada"),
]

MEDIO_NOTIF_CHOICES = [
    ("EMAIL", "Email"),
    ("SMS", "SMS"),
    ("WHATSAPP", "WhatsApp"),
    ("SISTEMA", "Sistema"),
]

ESTADO_NOTIF_CHOICES = [
    ("PENDIENTE", "Pendiente"),
    ("ENVIADO", "Enviado"),
    ("FALLIDO", "Fallido"),
    ("LEIDO", "Leído"),
]

DIA_SEMANA_CHOICES = [
    ("Lunes", "Lunes"),
    ("Martes", "Martes"),
    ("Miercoles", "Miércoles"),
    ("Jueves", "Jueves"),
    ("Viernes", "Viernes"),
    ("Sabado", "Sábado"),
    ("Domingo", "Domingo"),
]

class Cita(models.Model):
    TIPO_CITA = [
        ('PRESENCIAL', 'PRESENCIAL'),
        ('TELECONSULTA', 'TELECONSULTA'),
        ('DOMICILIO', 'DOMICILIO'),
        ('OTRO', 'OTRO'),
    ]
    
    ESTADO_CITA = [
        ('PENDIENTE', 'PENDIENTE'),
        ('CONFIRMADA', 'CONFIRMADA'),
        ('ATENDIDA', 'ATENDIDA'),
        ('CANCELADA', 'CANCELADA'),
        ('NO_ASISTE', 'NO_ASISTE'),
        ('REPROGRAMADA', 'REPROGRAMADA'),
    ]
    
    id_cita = models.AutoField(primary_key=True)
    id_paciente = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_paciente', db_column='id_paciente')
    id_doctor = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_doctor', db_column='id_doctor')
    id_horario = models.ForeignKey(
    'Medessentia.HorarioDoctor',  
    on_delete=models.RESTRICT,
    related_name='citas',
    db_column='id_horario',
    null=True,
    blank=True  
    )
    fecha_hora = models.DateTimeField()
    tipo_cita = models.CharField(max_length=20, choices=TIPO_CITA, default='PRESENCIAL')
    estado = models.CharField(max_length=20, choices=ESTADO_CITA, default='PENDIENTE')
    motivo = models.TextField(null=True, blank=True)
    observaciones = models.TextField(null=True, blank=True)
    registrado_por = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_registradas', db_column='registrado_por')
    fecha_registro = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'cita'

    def __str__(self):
        return f'Cita {self.id_cita} - {self.id_paciente} con {self.id_doctor}'

   
    def esta_disponible(self):
        """Verifica si el horario de la cita sigue disponible"""
        if self.id_horario:
           
            citas_conflicto = Cita.objects.filter(
                id_horario=self.id_horario,
                estado__in=['PENDIENTE', 'CONFIRMADA']
            ).exclude(id_cita=self.id_cita)
            return not citas_conflicto.exists()
        return True

    @classmethod
    def agendar_desde_horario(cls, horario_id, paciente, motivo=""):
        """Método simple para agendar desde un horario"""
        from datetime import datetime
        
        horario = HorarioDoctor.objects.get(id_horario=horario_id)
        
        cita = cls.objects.create(
            id_paciente=paciente,
            id_doctor=horario.id_doctor,
            id_horario=horario,
            fecha_hora=datetime.combine(horario.fecha_inicio, horario.hora_inicio),
            motivo=motivo,
            registrado_por=paciente
        )
        return cita
class HorarioDoctor(models.Model):
    id_horario = models.AutoField(primary_key=True)

    id_doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='horarios',
        db_column='id_doctor'
    )

    DIAS_SEMANA = [
        ('Lunes', 'Lunes'),
        ('Martes', 'Martes'),
        ('Miercoles', 'Miércoles'),  
        ('Jueves', 'Jueves'),
        ('Viernes', 'Viernes'),
        ('Sabado', 'Sábado'),        
        ('Domingo', 'Domingo'),
    ]

    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()
    dia_semana = models.CharField(max_length=12, choices=DIAS_SEMANA)
    hora_inicio = models.TimeField()
    hora_fin = models.TimeField()
    tipo_horario = models.CharField(
        max_length=20,
        choices=[('TRABAJO', 'Trabajo'), ('ALMUERZO', 'Almuerzo'), ('DESCANSO', 'Descanso')],
        default='TRABAJO'
    )
    es_recurrente = models.BooleanField(default=False)

    class Meta:
        db_table = 'horario_doctor'

    def __str__(self):
        return f'{self.get_dia_semana_display()} {self.hora_inicio} - {self.hora_fin} ({self.id_doctor})'

class Cie10(models.Model):
    id_cie10 = models.AutoField(primary_key=True)
    codigo = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField()

    class Meta:
        db_table = 'cie10'      
        managed = False           
        verbose_name = 'CIE-10'
        verbose_name_plural = 'Códigos CIE-10'

    def __str__(self):
        return f"{self.codigo} - {self.descripcion[:50]}"

# --- Historia Clínica ---
class HistoriaClinica(models.Model):
    """
    Historia Clínica: UN REGISTRO POR PACIENTE
    Contiene datos demográficos y antecedentes que no cambian frecuentemente
    """
    SEXO_CHOICES = [
        ('MASCULINO', 'Masculino'),
        ('FEMENINO', 'Femenino'),
        ('INTERSEXUAL', 'Intersexual'),
    ]
    
    ESTADO_CIVIL_CHOICES = [
        ('SOLTERO', 'Soltero/a'),
        ('CASADO', 'Casado/a'),
        ('DIVORCIADO', 'Divorciado/a'),
        ('VIUDO', 'Viudo/a'),
        ('UNION_LIBRE', 'Unión Libre'),
    ]
    
    NIVEL_INSTRUCCION_CHOICES = [
        ('NINGUNO', 'Ninguno'),
        ('PRIMARIA', 'Primaria'),
        ('SECUNDARIA', 'Secundaria'),
        ('SUPERIOR', 'Superior'),
        ('POSTGRADO', 'Postgrado'),
    ]
    
    TIPO_SEGURO_CHOICES = [
        ('NINGUNO', 'Ninguno'),
        ('MSP', 'MSP'),
        ('IESS', 'IESS'),
        ('PRIVADO', 'Privado'),
    ]
    
    # Identificación
    id_historia = models.AutoField(primary_key=True)
    id_paciente = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='historia_clinica',  # Nombre relacionado para acceder desde User
        verbose_name='Paciente',
        db_column='id_paciente'
    )
    expediente_no = models.CharField(
        max_length=50, 
        unique=True,
        verbose_name='Número de Expediente'
    )
    
    # Datos Demográficos
    nombres_completos = models.CharField(max_length=150, blank=True, null=True)
    cedula = models.CharField(max_length=20, blank=True, null=True, db_index=True)
    fecha_nacimiento = models.DateField(blank=True, null=True)
    sexo_biologico = models.CharField(max_length=20, choices=SEXO_CHOICES)
    genero = models.CharField(max_length=30, blank=True, null=True)
    estado_civil = models.CharField(
        max_length=30, 
        choices=ESTADO_CIVIL_CHOICES, 
        blank=True, 
        null=True
    )
    
    # Contacto
    direccion = models.TextField(blank=True, null=True)
    telefono = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(max_length=100, blank=True, null=True)
    contacto_emergencia = models.CharField(max_length=120, blank=True, null=True)
    
    # Información Social
    nivel_instruccion = models.CharField(
        max_length=100, 
        choices=NIVEL_INSTRUCCION_CHOICES,
        blank=True, 
        null=True
    )
    ocupacion = models.CharField(max_length=100, blank=True, null=True)
    tipo_seguro = models.CharField(
        max_length=20,
        choices=TIPO_SEGURO_CHOICES,
        default='NINGUNO'
    )
    
    # Antecedentes (información que raramente cambia)
    antecedentes_personales = models.TextField(
        blank=True, 
        null=True,
        help_text='Patológicos, quirúrgicos, traumáticos, alérgicos'
    )
    antecedentes_familiares = models.TextField(
        blank=True, 
        null=True,
        help_text='Enfermedades hereditarias'
    )
    antecedentes_obstetricos = models.TextField(
        blank=True, 
        null=True,
        help_text='Solo para pacientes femeninas: gestas, partos, cesáreas, abortos'
    )
    antecedentes_ginecologicos = models.TextField(
        blank=True, 
        null=True,
        help_text='Solo para pacientes femeninas: menarquia, FUR, PAP, ciclos'
    )
    vacunacion = models.TextField(blank=True, null=True)
    
   
    creado_por = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='historias_clinicas_creadas',
        db_column='creado_por' 
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    actualizado_por = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='historias_clinicas_actualizadas',
        blank=True,
        null=True,
        db_column='actualizado_por'
    )
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'historia_clinica'
        verbose_name = 'Historia Clínica'
        verbose_name_plural = 'Historias Clínicas'
        ordering = ['-fecha_creacion']
        indexes = [
            models.Index(fields=['cedula']),
            models.Index(fields=['expediente_no']),
            models.Index(fields=['id_paciente']),
        ]
    
    def __str__(self):
        return f"{self.expediente_no} - {self.nombres_completos or self.id_paciente.get_full_name()}"
    
    def get_edad_actual(self):
        """Calcula la edad actual del paciente"""
        if self.fecha_nacimiento:
            hoy = date.today()
            edad = hoy.year - self.fecha_nacimiento.year
            if hoy.month < self.fecha_nacimiento.month or \
               (hoy.month == self.fecha_nacimiento.month and hoy.day < self.fecha_nacimiento.day):
                edad -= 1
            return edad
        return None  # Mejor no devolver un valor predeterminado de edad en caso de que no haya fecha de nacimiento


# --- Atención Médica ---
class AtencionMedica(models.Model):
    """
    Atención Médica: MULTIPLES REGISTROS POR HISTORIA CLÍNICA
    Cada consulta/visita del paciente genera una atención
    """
    
    TIPO_ATENCION_CHOICES = [
        ('PRIMERA_VEZ', 'Primera Vez'),
        ('CONTROL', 'Control'),
        ('EMERGENCIA', 'Emergencia'),
        ('TELECONSULTA', 'Teleconsulta'),
    ]
    
    DIAGNOSTICO_CONDICION_CHOICES = [
        ('PRESUNTIVO', 'Presuntivo'),
        ('DEFINITIVO_INICIAL', 'Definitivo Inicial'),
        ('DEFINITIVO_CONFIRMADO_LAB', 'Definitivo Confirmado por Laboratorio'),
        ('DEFINITIVO_CONTROL', 'Definitivo de Control'),
    ]
    
    DIAGNOSTICO_CRONOLOGIA_CHOICES = [
        ('PRIMERA', 'Primera'),
        ('SUBSECUENTE', 'Subsiguiente'),
    ]
    
    # Identificación
    id_atencion = models.AutoField(primary_key=True)
    id_historia = models.ForeignKey(
        HistoriaClinica,
        on_delete=models.CASCADE,
        related_name='atenciones',
        db_column='id_historia'
    )
    id_paciente = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='atenciones_paciente',
        db_column='id_paciente'
    )
    id_doctor = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='atenciones_doctor',
        verbose_name='Doctor que atendió',
        db_column='id_doctor'
    )
    id_cita = models.IntegerField(null=True, blank=True, verbose_name='ID de Cita')
    
    # Datos de la atención
    fecha_atencion = models.DateTimeField(
        default=timezone.now,
        verbose_name='Fecha y Hora de Atención'
    )
    tipo_atencion = models.CharField(
        max_length=20,
        choices=TIPO_ATENCION_CHOICES,
        default='PRIMERA_VEZ',
        verbose_name='Tipo de Atención'
    )
    
    # Motivo de consulta
    motivo_consulta = models.TextField(
        verbose_name='Motivo de Consulta'
    )
    enfermedad_actual = models.TextField(
        blank=True, null=True,
        verbose_name='Enfermedad Actual'
    )
    
    # Signos vitales
    presion_sistolica = models.CharField(
        max_length=10, blank=True, null=True,
        verbose_name='Presión Sistólica'
    )
    presion_diastolica = models.CharField(
        max_length=10, blank=True, null=True,
        verbose_name='Presión Diastólica'
    )
    presion_media = models.CharField(
        max_length=10, blank=True, null=True,
        verbose_name='Presión Media'
    )
    temperatura = models.DecimalField(
        max_digits=4, decimal_places=1, blank=True, null=True,
        verbose_name='Temperatura (°C)'
    )
    frecuencia_respiratoria = models.IntegerField(
        blank=True, null=True,
        verbose_name='Frecuencia Respiratoria (rpm)'
    )
    frecuencia_cardiaca = models.IntegerField(
        blank=True, null=True,
        verbose_name='Frecuencia Cardíaca (lpm)'
    )
    saturacion_oxigeno = models.IntegerField(
        blank=True, null=True,
        verbose_name='Saturación de Oxígeno (%)'
    )
    peso = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True,
        verbose_name='Peso (kg)'
    )
    talla = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True,
        verbose_name='Talla (cm)'
    )
    imc = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True,
        verbose_name='Índice de Masa Corporal'
    )
    glucosa_capilar = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True,
        verbose_name='Glucosa Capilar (mg/dL)'
    )
    hemoglobina = models.DecimalField(
        max_digits=5, decimal_places=2, blank=True, null=True,
        verbose_name='Hemoglobina (g/dL)'
    )
    
    # Examen físico por sistemas
    organos_sentidos = models.TextField(blank=True, null=True, verbose_name='Órganos de los Sentidos')
    respiratorio = models.TextField(blank=True, null=True, verbose_name='Sistema Respiratorio')
    cardiovascular = models.TextField(blank=True, null=True, verbose_name='Sistema Cardiovascular')
    digestivo = models.TextField(blank=True, null=True, verbose_name='Sistema Digestivo')
    genital = models.TextField(blank=True, null=True, verbose_name='Sistema Genital')
    urinario = models.TextField(blank=True, null=True, verbose_name='Sistema Urinario')
    esqueletico = models.TextField(blank=True, null=True, verbose_name='Sistema Esquelético')
    muscular = models.TextField(blank=True, null=True, verbose_name='Sistema Muscular')
    nervioso = models.TextField(blank=True, null=True, verbose_name='Sistema Nervioso')
    endocrino = models.TextField(blank=True, null=True, verbose_name='Sistema Endocrino')
    hemo_linfatico = models.TextField(blank=True, null=True, verbose_name='Sistema Hemolinfático')
    tegumentario = models.TextField(blank=True, null=True, verbose_name='Sistema Tegumentario')
    
    # Examenes específicos
    examen_frontal = models.TextField(blank=True, null=True, verbose_name='Examen Frontal')
    examen_posterior = models.TextField(blank=True, null=True, verbose_name='Examen Posterior')
    examen_general = models.TextField(blank=True, null=True, verbose_name='Examen General')
    examen_neurologico = models.TextField(blank=True, null=True, verbose_name='Examen Neurológico')
    
    # Resultados
    resultado_laboratorio = models.TextField(blank=True, null=True, verbose_name='Resultados de Laboratorio')
    resultado_imagenologia = models.TextField(blank=True, null=True, verbose_name='Resultados de Imagenología')
    resultado_histopatologia = models.TextField(blank=True, null=True, verbose_name='Resultados de Histopatología')
    
    # Diagnóstico
    cie10_codigo = models.CharField(max_length=10, blank=True, null=True, verbose_name='Código CIE-10')
    cie10_descripcion = models.CharField(max_length=255, blank=True, null=True, verbose_name='Descripción CIE-10')
    diagnostico_observaciones = models.TextField(blank=True, null=True, verbose_name='Observaciones del Diagnóstico')
    diagnostico_condicion = models.CharField(
        max_length=30,
        choices=DIAGNOSTICO_CONDICION_CHOICES,
        blank=True, null=True,
        verbose_name='Condición del Diagnóstico'
    )
    diagnostico_cronologia = models.CharField(
        max_length=20,
        choices=DIAGNOSTICO_CRONOLOGIA_CHOICES,
        blank=True, null=True,
        verbose_name='Cronología del Diagnóstico'
    )
    
    # Plan y tratamiento
    plan_tratamiento = models.TextField(blank=True, null=True, verbose_name='Plan de Tratamiento')
    tratamiento_no_farmacologico = models.TextField(
        blank=True, null=True,
        verbose_name='Tratamiento No Farmacológico'
    )
    evolucion = models.TextField(blank=True, null=True, verbose_name='Evolución')
    pronostico = models.TextField(blank=True, null=True, verbose_name='Pronóstico')
    
    # Auditoría
    creado_por = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='atenciones_creadas',
        db_column='creado_por'
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    actualizado_por = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='atenciones_actualizadas',
        blank=True, null=True,
        db_column='actualizado_por'
    )
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'atencion'
        verbose_name = 'Atención Médica'
        verbose_name_plural = 'Atenciones Médicas'
        ordering = ['-fecha_atencion']
        indexes = [
            models.Index(fields=['id_historia']),
            models.Index(fields=['id_paciente']),
            models.Index(fields=['fecha_atencion']),
            models.Index(fields=['tipo_atencion']),
        ]
    
    def __str__(self):
        return f"Atención {self.id_atencion} - {self.id_historia.expediente_no} ({self.fecha_atencion.strftime('%d/%m/%Y')})"
    
    def calcular_imc(self):
        """Calcula el IMC si hay peso y talla"""
        if self.peso and self.talla and self.talla > 0:
            talla_metros = self.talla / 100  # Convertir cm a m
            return self.peso / (talla_metros * talla_metros)
        return None
    
    def get_edad_paciente_en_atencion(self):
        """Calcula la edad del paciente al momento de la atención"""
        if self.id_historia.fecha_nacimiento:
            edad = self.fecha_atencion.year - self.id_historia.fecha_nacimiento.year
            if self.fecha_atencion.month < self.id_historia.fecha_nacimiento.month or \
               (self.fecha_atencion.month == self.id_historia.fecha_nacimiento.month and 
                self.fecha_atencion.day < self.id_historia.fecha_nacimiento.day):
                edad -= 1
            return edad
        return None

class Receta(models.Model):
    class Estado(models.TextChoices):
        ACTIVA = 'ACTIVA', 'Activa'
        ANULADA = 'ANULADA', 'Anulada'
        SURTIDA = 'SURTIDA', 'Surtida'
    
    id_receta = models.AutoField(primary_key=True)
    id_atencion = models.IntegerField()
    id_paciente = models.IntegerField()
    id_doctor = models.IntegerField()
    fecha_emision = models.DateTimeField(auto_now_add=True)
    motivo = models.CharField(max_length=200, null=True, blank=True)
    indicaciones_generales = models.TextField(null=True, blank=True)
    observaciones = models.TextField(null=True, blank=True)
    estado = models.CharField(
        max_length=10,
        choices=Estado.choices,
        default=Estado.ACTIVA
    )
    creado_por = models.IntegerField()
    actualizado_por = models.IntegerField()
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'receta'
        verbose_name = 'Receta'
        verbose_name_plural = 'Recetas'
    
    def __str__(self):
        return f"Receta #{self.id_receta} - Paciente: {self.id_paciente}"


class RecetaDetalle(models.Model):
    id_detalle = models.AutoField(primary_key=True)
    id_receta = models.ForeignKey(
        Receta,
        on_delete=models.CASCADE,
        db_column='id_receta',
        related_name='detalles'
    )
    medicamento = models.CharField(max_length=150)
    concentracion = models.CharField(max_length=50, null=True, blank=True)
    presentacion = models.CharField(max_length=50, null=True, blank=True)
    dosis = models.CharField(max_length=50)
    frecuencia = models.CharField(max_length=100)
    duracion_dias = models.IntegerField()
    cantidad_total = models.IntegerField()
    via_administracion = models.CharField(max_length=50)
    indicaciones = models.TextField(null=True, blank=True)
    advertencias = models.TextField(null=True, blank=True)
    orden = models.IntegerField(default=0)
    
    class Meta:
        db_table = 'receta_detalle'
        verbose_name = 'Detalle de Receta'
        verbose_name_plural = 'Detalles de Recetas'
        ordering = ['orden']
    
    def __str__(self):
        return f"{self.medicamento} - {self.dosis}"
# --- Certificado Médico ---
class CertificadoMedico(models.Model):
    TIPO_CERTIFICADO_CHOICES = [
        ('REPOSO', 'Certificado de Reposo'),
        ('APTITUD', 'Certificado de Aptitud'),
        ('ENFERMEDAD', 'Certificado de Enfermedad'),
        ('DISCAPACIDAD', 'Certificado de Discapacidad'),
        ('OTRO', 'Otro Tipo de Certificado'),
    ]
    
    ESTADO_CHOICES = [
        ('ACTIVO', 'Activo'),
        ('ANULADO', 'Anulado'),
    ]
    
    id_certificado = models.AutoField(primary_key=True)
    id_atencion = models.ForeignKey(
        'AtencionMedica',  # Usa string si el modelo está en el mismo archivo
        on_delete=models.CASCADE,
        related_name='certificados',
        db_column='id_atencion',
        verbose_name='Atención Médica',
        blank=True,  # ← Agregar esto
        null=True    # ← Agregar esto
    )
    id_paciente = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='certificados_paciente',
        db_column='id_paciente',
        verbose_name='Paciente'
    )
    id_doctor = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='certificados_doctor',
        db_column='id_doctor',
        verbose_name='Doctor'
    )
    
    # Fechas
    fecha_emision = models.DateField(verbose_name='Fecha de Emisión')
    hora_emision = models.TimeField(verbose_name='Hora de Emisión')
    
    # Datos del certificado
    tipo_certificado = models.CharField(
        max_length=20,
        choices=TIPO_CERTIFICADO_CHOICES,
        default='REPOSO',
        verbose_name='Tipo de Certificado'
    )
    motivo = models.TextField(verbose_name='Motivo del Certificado')
    diagnostico = models.TextField(blank=True, null=True, verbose_name='Diagnóstico')
    
    # Datos específicos para reposo
    dias_reposo = models.IntegerField(blank=True, null=True, verbose_name='Días de Reposo')
    fecha_inicio_reposo = models.DateField(blank=True, null=True, verbose_name='Fecha Inicio Reposo')
    fecha_fin_reposo = models.DateField(blank=True, null=True, verbose_name='Fecha Fin Reposo')
    
    # Información adicional
    indicaciones = models.TextField(blank=True, null=True, verbose_name='Indicaciones')
    observaciones = models.TextField(blank=True, null=True, verbose_name='Observaciones')
    
    # Estado
    estado = models.CharField(
        max_length=10,
        choices=ESTADO_CHOICES,
        default='ACTIVO',
        verbose_name='Estado del Certificado'
    )
    
    # Auditoría
    creado_por = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='certificados_creados',
        db_column='creado_por'
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'certificado_medico'
        verbose_name = 'Certificado Médico'
        verbose_name_plural = 'Certificados Médicos'
        ordering = ['-fecha_emision', '-hora_emision']
        indexes = [
            models.Index(fields=['id_atencion']),
            models.Index(fields=['id_paciente']),
            models.Index(fields=['fecha_emision']),
            models.Index(fields=['tipo_certificado']),
            models.Index(fields=['estado']),
        ]
    
    def __str__(self):
        return f"Certificado {self.id_certificado} - {self.get_tipo_certificado_display()} - {self.id_paciente.get_full_name()}"
    
    def get_paciente_nombre(self):
        """Obtiene el nombre completo del paciente"""
        try:
            # Intentar obtener desde perfil
            if hasattr(self.id_paciente, 'perfil') and self.id_paciente.perfil:
                perfil = self.id_paciente.perfil
                
                # Buscar diferentes variaciones de campos
                if hasattr(perfil, 'nombres_completos') and perfil.nombres_completos:
                    return perfil.nombres_completos
                
                if hasattr(perfil, 'nombres') and hasattr(perfil, 'apellidos'):
                    return f"{perfil.nombres} {perfil.apellidos}".strip()
                
                if hasattr(perfil, 'primer_nombre') and hasattr(perfil, 'primer_apellido'):
                    nombre = f"{perfil.primer_nombre} {getattr(perfil, 'segundo_nombre', '')} {perfil.primer_apellido} {getattr(perfil, 'segundo_apellido', '')}"
                    return ' '.join(nombre.split())
            
            # Usar campos del User
            nombre = f"{self.id_paciente.first_name} {self.id_paciente.last_name}".strip()
            return nombre if nombre else self.id_paciente.username
        except:
            return self.id_paciente.username

    def get_doctor_nombre(self):
        """Obtiene el nombre completo del doctor"""
        try:
            # Intentar obtener desde perfil
            if hasattr(self.id_doctor, 'perfil') and self.id_doctor.perfil:
                perfil = self.id_doctor.perfil
                
                if hasattr(perfil, 'nombres_completos') and perfil.nombres_completos:
                    return perfil.nombres_completos
                
                if hasattr(perfil, 'nombres') and hasattr(perfil, 'apellidos'):
                    return f"{perfil.nombres} {perfil.apellidos}".strip()
                
                if hasattr(perfil, 'primer_nombre') and hasattr(perfil, 'primer_apellido'):
                    nombre = f"{perfil.primer_nombre} {getattr(perfil, 'segundo_nombre', '')} {perfil.primer_apellido} {getattr(perfil, 'segundo_apellido', '')}"
                    return ' '.join(nombre.split())
            
            # Usar campos del User
            nombre = f"{self.id_doctor.first_name} {self.id_doctor.last_name}".strip()
            return nombre if nombre else self.id_doctor.username
        except:
            return self.id_doctor.username

    def get_codigo_certificado(self):
        """Genera código único del certificado"""
        try:
            return f"CERT-{self.id_certificado:06d}-{self.fecha_emision.strftime('%Y%m')}"
        except:
            return f"CERT-{self.id_certificado}"

    def calcular_fecha_fin_reposo(self):
        """Calcula fecha fin reposo automáticamente"""
        if self.dias_reposo and self.fecha_inicio_reposo:
            from datetime import timedelta
            return self.fecha_inicio_reposo + timedelta(days=self.dias_reposo)
        return None

    def anular(self, usuario, motivo):
        """Anula el certificado"""
        from django.utils import timezone
        self.estado = 'ANULADO'
        timestamp = timezone.now().strftime('%d/%m/%Y %H:%M')
        self.observaciones = f"{self.observaciones or ''}\n\nANULADO: {motivo} ({timestamp})"
        self.save()

    def es_valido(self):
        """Verifica si el certificado está activo y vigente"""
        if self.estado != 'ACTIVO':
            return False
        
        if self.tipo_certificado == 'REPOSO' and self.fecha_fin_reposo:
            from datetime import date
            return date.today() <= self.fecha_fin_reposo
        
        return True
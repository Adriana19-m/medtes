import os
import csv
from django.core.management.base import BaseCommand
from django.conf import settings
from Aplicaciones.Medessentia.models import Cie10


class Command(BaseCommand):
    help = "Carga o actualiza los códigos CIE-10 desde el archivo CSV incluido en el proyecto."

    def handle(self, *args, **kwargs):
        
        ruta_csv = os.path.join(
        settings.BASE_DIR,
        'Aplicaciones', 'Medessentia', 'static', 'datos', 'icd10cm-codes-2026.csv'
        )


        if not os.path.exists(ruta_csv):
            self.stdout.write(self.style.ERROR(f" No se encontró el archivo: {ruta_csv}"))
            return

        self.stdout.write(self.style.NOTICE(f" Leyendo archivo: {ruta_csv}"))

        cargados = 0
        actualizados = 0

        with open(ruta_csv, encoding='utf-8') as f:
            lector = csv.reader(f)
            for fila in lector:
                if len(fila) < 2:
                    continue
                codigo = fila[0].strip().replace('\t', '').replace(' ', '')
                descripcion = fila[1].strip()


                if not codigo or len(codigo) > 100:
                    continue

                obj, creado = Cie10.objects.update_or_create(
                    codigo=codigo,
                    defaults={'descripcion': descripcion}
                )
                if creado:
                    cargados += 1
                else:
                    actualizados += 1

        self.stdout.write(self.style.SUCCESS(
            f" Proceso completado. Nuevos: {cargados}, Actualizados: {actualizados}"
        ))

#VirusTotal IOC Checker

VirusTotal IOC Checker es una aplicación de escritorio basada en Tkinter que permite consultar varios Indicadores de Compromiso (IOCs) como hashes de archivos, URLs, dominios y direcciones IPv4 en la API de VirusTotal. La aplicación filtra automáticamente los IOCs desde la entrada del usuario y muestra los resultados de las consultas, indicando la cantidad de detecciones maliciosas reportadas por los proveedores de seguridad.

Funcionalidades

  Filtrado de IOCs:
  
      Hashes de archivos (MD5, SHA1, SHA256)
      URLs
      Dominios
      Direcciones IPv4
      
Consulta a VirusTotal:

      Realiza consultas a la API de VirusTotal para cada IOC filtrado.
      Muestra el número de detecciones maliciosas para cada IOC consultado.

  
Interfaz de Usuario:

      Entrada de API Key de VirusTotal.
      Área de texto para ingresar los IOCs.
      Botón para iniciar la consulta.
      Área de texto para mostrar los resultados.
      Botón para copiar los resultados al portapapeles.


Uso

      Clona este repositorio o descarga los archivos.
      Instala las dependencias necesarias (Tkinter y Requests).
      Ejecuta el script virus_total_checker.py.
      Introduce tu API Key de VirusTotal.
      Introduce los IOCs en el área de texto.
      Presiona el botón "Consultar" para realizar las consultas.
      Los resultados se mostrarán en el área de texto de resultados.
      Puedes copiar los resultados al portapapeles con el botón "Copiar Resultados".

Requisitos

      Python 3.x
      Tkinter
      Requests


![Filtrado de IOCs](https://github.com/Dani-Caste/virustotal-IOCs/assets/97344483/d621197d-fada-47b0-a7de-109587691544)

![IOCs por linea](https://github.com/Dani-Caste/virustotal-IOCs/assets/97344483/1994890a-c694-4233-8a90-d567f21eeb57)





      




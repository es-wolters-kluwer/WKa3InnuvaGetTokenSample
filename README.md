# ¡Bienvenido a3developer!
En esta aplicación ASP.NET Core de ejemplo te mostramos cómo funciona la autenticación OAuth 2.0 con OpenIdConnect.

# Requisitos 

Es imprescindible disponer de un client OAuth (puedes solicitarlo [aquí](https://forms.office.com/r/0jdxS8vyWN) y una Wolters Kluwer Account que tenga acceso a a3innuva. Si necesitás más información, puedes visitar nuestro [developer portal](https://a3developers.wolterskluwer.es/)

# Cómo probar la aplicación

Antes de poder probar la aplicación, edita el fichero ``appsettings.json para ajustarlo a tu configuración:
- ``ClientId``: especifica el nombre del client OAuth que te hemos asignado (p.e. WK.ES.A3WebApi.12345)
- ``ClientSecret``: secret del client OAuht (p.e. dyd4dktgzdFnfPIm)
- ``AuthenticationScopes``: los scopes varían en función de la aplicación a3innuva a la que quieres conectar:
	a3innuva | nómina: offline_access+openid+IDInfo+WK.ES.A3EquipoContex
	a3innuva | contabilidad: offline_access+openid+WK.ES.NEWPOL.COR.API+WK.ES.NEWPOL.ACC.API+WK.ES.NEWPOL.MNG.API+WK.ES.Webhooks

Una vez editado el fichero, ejecuta la aplicación y correrá por defecto en https://localhost:43971/ 

Es importante que no modifiques el puerto, ya que los client OAuth que proporcionamos desde WK admiten como redirect_uri https://localhost:43971/ por lo que si cambias el puerto o el path de callback, el servidor de autenticación de WKA te dará un mensaje de error.

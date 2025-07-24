@echo off
echo ===== PenteIA Scanner - Ferramenta de Teste =====
echo.

:menu
echo Selecione um alvo para testar:
echo 1. DVWA Local (http://localhost/DVWA/)
echo 2. OWASP Juice Shop (http://localhost:3000/)
echo 3. WebGoat (http://localhost:8080/WebGoat/)
echo 4. URL personalizada
echo 5. Sair
echo.
set /p escolha=Escolha uma opcao (1-5): 

if "%escolha%"=="1" goto dvwa
if "%escolha%"=="2" goto juiceshop
if "%escolha%"=="3" goto webgoat
if "%escolha%"=="4" goto custom
if "%escolha%"=="5" goto end

echo Opcao invalida. Tente novamente.
goto menu

:dvwa
echo.
echo Testando DVWA...
python scanner.py --url http://localhost/DVWA/ --auth auth_dvwa.json
goto end

:juiceshop
echo.
echo Testando OWASP Juice Shop...
python scanner.py --url http://localhost:3000/ --config exemplos/config_juiceshop.json
goto end

:webgoat
echo.
echo Testando WebGoat...
python scanner.py --url http://localhost:8080/WebGoat/ --config exemplos/config_webgoat.json
goto end

:custom
echo.
set /p url=Digite a URL completa para testar: 
echo.
echo Deseja usar autenticacao? (S/N)
set /p auth=Resposta: 

if /i "%auth%"=="S" (
    python scanner.py --url %url% --auth auth_dvwa.json
) else (
    python scanner.py --url %url%
)
goto end

:end
echo.
echo Teste concluido.
echo.
pause

@echo off
echo ===== PenteIA - Assistente de Treinamento de Modelo =====
echo.

echo Escolha uma opcao:
echo 1. Coletar dados e treinar modelo real
echo 2. Treinar modelo com dados existentes
echo 3. Usar modelo de demonstracao
echo 4. Sair
echo.
set /p escolha=Escolha uma opcao (1-4): 

if "%escolha%"=="1" goto coletar_treinar
if "%escolha%"=="2" goto treinar
if "%escolha%"=="3" goto demo
if "%escolha%"=="4" goto fim

echo Opcao invalida. Tente novamente.
goto fim

:coletar_treinar
echo.
echo === COLETANDO DADOS PARA TREINAMENTO ===
echo.
python collect_vulns.py
echo.
echo === TREINANDO MODELO ===
echo.
python treinar_modelo_real.py
goto fim

:treinar
echo.
echo === TREINANDO MODELO COM DADOS EXISTENTES ===
echo.
python treinar_modelo_real.py
goto fim

:demo
echo.
echo === CRIANDO MODELO DE DEMONSTRACAO ===
echo.
python criar_modelo_demo.py
goto fim

:fim
echo.
echo Operacao concluida.
echo.
pause

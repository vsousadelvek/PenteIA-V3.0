#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script para corrigir problemas de declaração nonlocal no arquivo treinar_modelo_real.py
"""
import re
import sys

# Abre o arquivo original
with open('treinar_modelo_real.py', 'r', encoding='utf-8') as f:
    conteudo = f.read()

# Conta quantas ocorrências de nonlocal existem
ocorrencias = conteudo.count('nonlocal ')
print(f"Encontradas {ocorrencias} ocorrências de 'nonlocal'")

# Substitui todas as declarações nonlocal por global
conteudo_corrigido = re.sub(r'nonlocal\s+([^\n]+)', r'global \1', conteudo)

# Verifica se houve mudanças
if conteudo != conteudo_corrigido:
    # Salva o arquivo corrigido
    with open('treinar_modelo_real.py', 'w', encoding='utf-8') as f:
        f.write(conteudo_corrigido)
    print("Arquivo corrigido com sucesso!")
else:
    print("Não foram encontradas ocorrências de 'nonlocal' para corrigir.")

print("\nAgora tente executar o arquivo treinar_modelo_real.py novamente.")

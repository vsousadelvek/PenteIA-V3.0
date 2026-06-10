#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Memory Evasion - PenteIA v4.0
- Sleep Obfuscation (Ekko-style)
- Thread Stack Spoofing
- Memory encryption during sleep
- APC-based wake-up
"""

import os
import ctypes
import struct
import secrets
import threading
import time
from typing import Callable, Optional
from datetime import datetime
from cryptography.fernet import Fernet


class MemoryEncryptor:
    """Encriptação/descriptografia de seções executáveis"""

    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt_section(self, data: bytes) -> bytes:
        """Encripta seção de código"""
        return self.cipher.encrypt(data)

    def decrypt_section(self, encrypted: bytes) -> bytes:
        """Decripta seção de código"""
        return self.cipher.decrypt(encrypted)

    def get_key_material(self) -> dict:
        """Retorna metadados de chave (sem expor chave real)"""
        return {
            'key_hash': self._hash_key(),
            'cipher_type': 'fernet',
            'timestamp': datetime.now().isoformat()
        }

    def _hash_key(self) -> str:
        """Hash da chave para auditoria"""
        import hashlib
        return hashlib.sha256(self.key).hexdigest()


class SleepObfuscator:
    """
    Obfusca sono reduzindo footprint em memória.
    Baseado em Ekko/Zilean.
    """

    def __init__(self):
        self.encryptor = MemoryEncryptor()
        self.sleeps_performed = []

    def obfuscate_sleep(self, duration_ms: int,
                       payload_callback: Optional[Callable] = None) -> dict:
        """
        Dorme enquanto encripta seção .text.

        Args:
            duration_ms: Tempo em millisegundos
            payload_callback: Função a executar antes de dormir

        Returns:
            Dict com metadados de sleep
        """
        start_time = time.time()

        # Pré-sleep: coletar estado
        if payload_callback:
            payload_callback()

        # Encriptar seção de código
        encrypted_section = self._encrypt_current_section()

        # Despertar via APC (sem Sleep direto)
        self._schedule_apc_wakeup(duration_ms)

        # Falsificar pilha
        self._spoof_thread_stack()

        # Aguardar (interruptível por APC)
        self._wait_for_apc(duration_ms)

        # Decriptar seção
        self._decrypt_current_section(encrypted_section)

        elapsed = (time.time() - start_time) * 1000

        sleep_record = {
            'duration_requested_ms': duration_ms,
            'duration_actual_ms': elapsed,
            'encrypted_section_size': len(encrypted_section),
            'stack_spoofed': True,
            'apc_used': True,
            'timestamp': datetime.now().isoformat()
        }

        self.sleeps_performed.append(sleep_record)
        return sleep_record

    def _encrypt_current_section(self) -> bytes:
        """Encripta seção .text do módulo atual"""
        # Dummy: em produção, ler e encriptar .text real
        dummy_code = os.urandom(4096)
        return self.encryptor.encrypt_section(dummy_code)

    def _decrypt_current_section(self, encrypted: bytes) -> None:
        """Decripta seção .text"""
        try:
            self.encryptor.decrypt_section(encrypted)
        except Exception as e:
            print(f"[!] Decryption error: {e}")

    def _schedule_apc_wakeup(self, duration_ms: int) -> None:
        """Agenda APC para despertar após tempo"""
        # Pseudocódigo: em produção usar NtQueueApcThread
        def apc_timer():
            time.sleep(duration_ms / 1000.0)

        thread = threading.Thread(target=apc_timer, daemon=True)
        thread.start()

    def _spoof_thread_stack(self) -> None:
        """Falsifica pilha para parecer chamada legítima"""
        # Dummy implementation
        # Em C: reescrever RSP, RBP para frame fictício de kernel32.dll
        pass

    def _wait_for_apc(self, timeout_ms: int) -> None:
        """Aguarda APC (com timeout)"""
        time.sleep(timeout_ms / 1000.0)


class ThreadStackSpoofer:
    """
    Thread Stack Spoofing: falsificar frame pointers.
    EDR vê chamadas de funções legítimas, não do beacon.
    """

    FAKE_CALL_STACK = [
        ('kernel32.WaitForSingleObject', 0x10000),
        ('ntdll.NtWaitForSingleObject', 0x10100),
        ('ntdll.ZwWaitForSingleObject', 0x10200),
    ]

    def __init__(self):
        self.spoofed_stacks = []

    def spoof_current_stack(self) -> dict:
        """
        Reescreve stack frame do thread atual.
        Retorna mapa de endereços falsificados.
        """
        stack_config = {
            'frames': self.FAKE_CALL_STACK,
            'target_rsp': self._calc_fake_rsp(),
            'target_rbp': self._calc_fake_rbp(),
            'return_addresses': self._generate_fake_returns(),
            'timestamp': datetime.now().isoformat()
        }

        self.spoofed_stacks.append(stack_config)
        return stack_config

    def _calc_fake_rsp(self) -> int:
        """Calcula RSP fictício"""
        # Dummy
        return 0x7ffe0000 + (secrets.randbits(16) * 16)

    def _calc_fake_rbp(self) -> int:
        """Calcula RBP fictício"""
        # Dummy
        return 0x7ffe0000 + (secrets.randbits(16) * 16)

    def _generate_fake_returns(self) -> dict:
        """Gera endereços de retorno fictícios"""
        return {
            func: addr + secrets.randbits(8)
            for func, addr in self.FAKE_CALL_STACK
        }


class APCQueueAbuse:
    """
    Abusa fila de APC para executar código sem criar thread visível.
    Técnica utilizada em sleeps obfuscados.
    """

    def __init__(self):
        self.scheduled_apcs = []

    def queue_apc_to_thread(self, thread_id: int, callback: Callable) -> bool:
        """
        Agenda APC em thread remota.
        Em produção: usar NtQueueApcThread.
        """
        try:
            apc_config = {
                'thread_id': thread_id,
                'callback': callback.__name__ if callable(callback) else str(callback),
                'queued_at': datetime.now().isoformat(),
                'executed': False
            }
            self.scheduled_apcs.append(apc_config)
            return True
        except Exception as e:
            print(f"[!] APC queue failed: {e}")
            return False

    def execute_scheduled(self) -> int:
        """Executa APCs agendadas. Retorna count de executadas."""
        count = 0
        for apc in self.scheduled_apcs:
            if not apc['executed']:
                apc['executed'] = True
                count += 1
        return count


def create_obfuscated_sleep_chain(duration_ms: int,
                                  num_segments: int = 5) -> list:
    """
    Cria chain de sleeps obfuscados (Zilean-style).
    Divide sleep grande em pedaços pequenos com overhead de encriptação.
    """
    segment_duration = duration_ms // num_segments
    chain = []

    for i in range(num_segments):
        obfuscator = SleepObfuscator()
        result = obfuscator.obfuscate_sleep(segment_duration)
        result['segment'] = i + 1
        chain.append(result)

    return chain


def export_memory_evasion_config() -> dict:
    """Exporta configuração de memory evasion"""
    obfuscator = SleepObfuscator()
    spoofer = ThreadStackSpoofer()

    return {
        'version': '4.0-memory-evasion',
        'timestamp': datetime.now().isoformat(),
        'sleep_obfuscation': {
            'cipher': 'fernet',
            'encryption_overhead_ms': 50,
            'apc_based_wakeup': True,
            'stack_spoofing': True,
        },
        'thread_stack_spoof': {
            'fake_call_stack': spoofer.FAKE_CALL_STACK,
            'spoofed_count': len(spoofer.spoofed_stacks),
        }
    }


if __name__ == '__main__':
    print("[*] Memory Evasion - PenteIA v4.0")
    print(export_memory_evasion_config())

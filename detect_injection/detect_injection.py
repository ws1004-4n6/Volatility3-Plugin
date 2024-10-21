#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'GyuBin Kim'
__email__ = 'ws1004@kakao.com'
__version__ = '1.0.0'

import sys, pefile
from colorama import Fore, Style, init

from volatility3.framework import interfaces, symbols, exceptions, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, vadinfo, modules, info
from volatility3.cli import text_renderer

init(autoreset=True)

class Detect_malware(interfaces.plugins.PluginInterface):

    _required_framework_version = (2,0,0)
    _version = (1,0,0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=['Intel32','Intel64'],
            ),
            requirements.BooleanRequirement(
                name="dll",
                description="Detect DLL Injection",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="thread",
                description="Detect Thread Injection",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="pe",
                description="Detect PE Injection",
                optional=True,
            ),
            requirements.PluginRequirement(
                name='pslist',
                plugin=pslist.PsList,
                version=(2,0,0)
            ),
            requirements.PluginRequirement(
                name='vadinfo',
                plugin=vadinfo.VadInfo,
                version=(2,0,0)
            ),
        ]

    @classmethod
    def hex_dump(cls, data, width=8):
        hex_str = data.hex()
        lines = []
        for i in range(0, len(hex_str), width * 2):
            line = hex_str[i:i + width * 2]
            hex_pairs = " ".join(line[j:j + 2] for j in range(0, len(line), 2))
            ascii_part = ''.join(chr(int(line[j:j + 2], 16)) if 32 <= int(line[j:j + 2], 16) <= 127 else '.' for j in range(0, len(line), 2))
            lines.append(f"{hex_pairs} {ascii_part}")
        return "\n".join(lines)

    @classmethod
    def get_kernel_modules(cls, context, layer_name, symbol_table):
        kernel_modules = {}
        for module in modules.Modules.list_modules(context, layer_name, symbol_table):
            try:
                module_name = module.FullDllName.get_string().lower()
                kernel_modules[module_name] = {
                    "Start_Virtual_Address" : hex(module.DllBase),
                    "End_Virtual_Address" : hex(module.DllBase + module.SizeOfImage),
                }
            except Exception as e:
                pass
        return kernel_modules
    
    @classmethod
    def get_proc_vads_list(cls, proc: interfaces.objects.ObjectInterface):
        proc_vads_list = []
        for vad in proc.get_vad_root().traverse():
            proc_vads_list.append(vad)
        return proc_vads_list

    @classmethod
    def get_proc_dll_list(cls, proc: interfaces.objects.ObjectInterface):
        proc_dll_list = []
        for entry in proc.load_order_modules():
            try:
                FullDllName = entry.FullDllName.get_string().lower()
                if FullDllName.split(".")[-1] != "exe":
                    proc_dll_list.append(FullDllName)
            except exceptions.InvalidAddressException:
                continue
        return proc_dll_list

    @classmethod
    def detect_dll_injection(cls, proc: interfaces.objects.ObjectInterface):
        result = ""
        dll_injection_flag = False
        proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
        pid = proc.UniqueProcessId
        ppid = proc.InheritedFromUniqueProcessId
        thread = proc.ActiveThreads
        
        result += f"{proc_name} | PID : {pid} | PPID : {ppid} | Threads : {thread} | "

        for entry in proc.load_order_modules():
            try:
                FullDllName = entry.FullDllName.get_string().lower()

                if FullDllName.split(".")[-1] == "exe":
                    result += f"{FullDllName}\n\nLdr Module : \t{FullDllName}\n"
                else:
                    loadreason = entry.LoadReason
                    obsoleteloadcount = entry.ObsoleteLoadCount
                    entrypointactivationcontext = entry.EntryPointActivationContext
                    protectdelayload = entry.ProtectDelayLoad
                    
                    if loadreason == 4 and obsoleteloadcount != 65535 and entrypointactivationcontext != 0 and protectdelayload == 0:
                        dll_injection_flag = True
                        result += f"\t\t{Fore.RED}{FullDllName}(By LoadLibrary + Suspect){Style.RESET_ALL}\n"
                    elif loadreason == 4 and obsoleteloadcount != 65535:
                        result += f"\t\t{FullDllName}{Fore.YELLOW}(By LoadLibrary){Style.RESET_ALL}\n"
                    else:
                        result += f"\t\t{FullDllName}\n"
            except (exceptions.InvalidAddressException, AttributeError):
                continue

        if dll_injection_flag:
            return print(result)
        else:
            return None
    
    @classmethod
    def detect_thread_injection(
        cls, 
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        symbol_table: str,
        proc: interfaces.objects.ObjectInterface,
    ):
        result = ""
        suspect_flag = False
        suspend_flag = False
        pid = proc.UniqueProcessId
        ppid = proc.InheritedFromUniqueProcessId
        thread = proc.ActiveThreads
        proc_layer = context.layers[proc.add_process_layer()]
        proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
        thread_list = proc.ThreadListHead.to_list(symbol_table + constants.BANG + "_ETHREAD", "ThreadListEntry")
        
        for vad in proc.get_vad_root().traverse():
            protection_string = vad.get_protection(
                vadinfo.VadInfo.protect_values(context, kernel_layer_name, symbol_table),
                vadinfo.winnt_protections,
            )
            execute_readwrite = "READ" in protection_string and "WRITE" in protection_string and "EXECUTE" in protection_string

            if execute_readwrite and vad.get_private_memory() == True and vad.get_tag() == "VadS" and vad.get_commit_charge() != 0:
                suspect_flag = True
                for ethread in thread_list:
                    if ethread.Tcb.State == 5 and ethread.Tcb.WaitReason == 5 and ethread.Tcb.SuspendCount != 0:
                        suspend_flag = True
                if suspend_flag:
                    result += f"{proc_name} | PID : {pid} | PPID : {ppid} | Threads : {thread} | {next(proc.load_order_modules()).FullDllName.get_string().lower()}{Fore.RED} (Suspend){Style.RESET_ALL}\n"
                else:
                    result += f"{proc_name} | PID : {pid} | PPID : {ppid} | Threads : {thread} | {next(proc.load_order_modules()).FullDllName.get_string().lower()}\n"

                data = proc_layer.read(vad.get_start(), 64, pad=True)
                result += f"{cls.hex_dump(data)}\n"

                if not symbols.symbol_table_is_64bit(context, symbol_table): architecture = "intel"
                else: architecture = "intel64"

                disasm = interfaces.renderers.Disassembly(data, vad.get_start(), architecture)
                result += f"{text_renderer.display_disassembly(disasm)}\n\n"
            
        if suspect_flag:
            return print(result)
        else:
            return None
    
    @classmethod
    def detect_pe_injection(
        cls, 
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        symbol_table: str,
        proc: interfaces.objects.ObjectInterface,
    ):
        def is_pe_file(data):
            try:
                pe = pefile.PE(data=data)
                return True
            except:
                return False
        
        result = ""
        suspect_flag = False
        pid = proc.UniqueProcessId
        ppid = proc.InheritedFromUniqueProcessId
        thread = proc.ActiveThreads
        proc_layer = context.layers[proc.add_process_layer()]
        proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
        
        for vad in proc.get_vad_root().traverse():
            protection_string = vad.get_protection(
                vadinfo.VadInfo.protect_values(context, kernel_layer_name, symbol_table),
                vadinfo.winnt_protections,
            )
            execute_readwrite = "READ" in protection_string and "WRITE" in protection_string and "EXECUTE" in protection_string

            if execute_readwrite and vad.get_private_memory() == True and vad.get_tag() == "VadS":
                pe_header_data = proc_layer.read(vad.get_start(),512, pad=True)
                if is_pe_file(pe_header_data):
                    try:
                        file_object = vad.Subsection.ControlArea.FilePointer.dereference().cast("_FILE_OBJECT")
                        continue
                    except:
                        suspect_flag = True
                        result += f"{proc_name} | PID : {pid} | PPID : {ppid} | Threads : {thread} | {next(proc.load_order_modules()).FullDllName.get_string().lower()}{Fore.RED} (By PE Injection){Style.RESET_ALL}\n"
                        data = proc_layer.read(vad.get_start(),64, pad=True)
                        result += f"{cls.hex_dump(data)}\n"
                        
                        if not symbols.symbol_table_is_64bit(context, symbol_table): architecture = "intel"
                        else: architecture = "intel64"

                        disasm = interfaces.renderers.Disassembly(data, vad.get_start(), architecture)
                        result += f"{text_renderer.display_disassembly(disasm)}"
        if suspect_flag:
            return print(result)
        else:
            return None

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]
        context = self.context
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name

        if self.config.get("dll", None):
            print(f"{Fore.YELLOW}========================================= DLL INJECTION ========================================== {Style.RESET_ALL}")
            for proc in procs:
                self.detect_dll_injection(proc)
            print(f"{Fore.YELLOW}================================================================================================== {Style.RESET_ALL}")
        elif self.config.get("thread", None):
            print(f"{Fore.YELLOW}======================================== THREAD INJECTION ======================================== {Style.RESET_ALL}")
            for proc in procs:
                self.detect_thread_injection(context, layer_name, symbol_table, proc)
            print(f"{Fore.YELLOW}================================================================================================== {Style.RESET_ALL}")
        elif self.config.get("pe", None):
            print(f"{Fore.YELLOW}========================================== PE INJECTION ========================================== {Style.RESET_ALL}")
            for proc in procs:
                self.detect_pe_injection(context, layer_name, symbol_table, proc)
            print(f"{Fore.YELLOW}================================================================================================== {Style.RESET_ALL}")

        yield (0,("Analysis complete!!",))

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        if not (self.config.get("dll", None) or self.config.get("thread", None) or self.config.get("pe", None)):
            print("At least one option (dll, thread, or pe) must be set.\nUse -h for more information.")
            sys.exit(1)

        return renderers.TreeGrid(
            [
                ("Analyzing...", str),
            ], 
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table = kernel.symbol_table_name,
                    filter_func = filter_func,
                )
            )
        )
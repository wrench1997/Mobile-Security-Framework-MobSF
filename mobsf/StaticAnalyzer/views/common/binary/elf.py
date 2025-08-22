# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)
from mobsf.MobSF.utils import (
    run_with_timeout,
)

from django.conf import settings


NA = '不适用'
NO_RELRO = '无RELRO'
PARTIAL_RELRO = '部分RELRO'
FULL_RELRO = '完全RELRO'
INFO = '信息'
WARNING = '警告'
HIGH = '高危'


def nm_is_debug_symbol_stripped(elf_file):
    """使用操作系统工具检查调试符号是否被剥离。"""
    # https://linux.die.net/man/1/nm
    out = subprocess.check_output(
        [shutil.which('nm'), '--debug-syms', elf_file],
        stderr=subprocess.STDOUT)
    return b'no debug symbols' in out


class ELFChecksec:
    def __init__(self, elf_file, so_rel):
        self.elf_path = elf_file.as_posix()
        self.elf_rel = so_rel
        self.elf = run_with_timeout(
            lief.parse,
            settings.BINARY_ANALYSIS_TIMEOUT,
            self.elf_path)

    def checksec(self):
        elf_dict = {}
        elf_dict['name'] = self.elf_rel
        if not self.is_elf(self.elf_path):
            return
        is_nx = self.is_nx()
        if is_nx:
            severity = INFO
            desc = (
                '该二进制文件已设置NX位。这会将内存页标记为不可执行，'
                '使攻击者注入的shellcode无法执行。')
        else:
            severity = HIGH
            desc = (
                '该二进制文件未设置NX位。NX位通过将内存页标记为不可执行，'
                '提供了对内存损坏漏洞利用的保护。'
                '使用选项--noexecstack或-z noexecstack将栈标记为不可执行。')
        elf_dict['nx'] = {
            'is_nx': is_nx,
            'severity': severity,
            'description': desc,
        }
        severity = '信息'
        is_pie = self.is_pie()
        if is_pie == 'dso':
            is_pie = '动态共享对象(DSO)'
            desc = (
                '该共享对象使用-fPIC标志构建，启用了位置独立代码。'
                '这使得面向返回的编程(ROP)攻击更难以可靠地执行。')
        elif is_pie == 'pie':
            is_pie = '位置独立可执行文件(PIE)'
            desc = (
                '该共享对象使用-fPIC标志构建，启用了位置独立代码。'
                '这使得面向返回的编程(ROP)攻击更难以可靠地执行。')
        elif is_pie == 'rel':
            is_pie = '可重定位目标文件'
            desc = (
                '该共享对象使用-fPIC标志构建，启用了位置独立代码。'
                '这使得面向返回的编程(ROP)攻击更难以可靠地执行。')
        elif is_pie == 'no':
            is_pie = '无PIE'
            severity = '高危'
            desc = (
                '该共享对象构建时未使用位置独立代码标志。为了防止'
                '攻击者可靠地跳转到特定的被利用函数，地址空间布局'
                '随机化(ASLR)会随机排列进程关键数据区域的地址空间位置，'
                '包括可执行文件的基址以及栈、堆和库的位置。使用编译器'
                '选项-fPIC启用位置独立代码。')
        elf_dict['pie'] = {
            'is_pie': is_pie,
            'severity': severity,
            'description': desc,
        }
        has_canary = self.has_canary()
        if has_canary:
            severity = INFO
            desc = (
                '该二进制文件在栈中添加了栈保护值(canary)，'
                '当栈缓冲区溢出覆盖返回地址时，该值也会被覆盖。'
                '这允许通过在函数返回前验证canary的完整性来检测溢出。')
        else:
            severity = HIGH
            desc = (
                '该二进制文件在栈中没有添加栈保护值(canary)。栈保护值'
                '用于检测和防止漏洞利用覆盖返回地址。使用选项'
                '-fstack-protector-all启用栈保护。'
                '除非使用Dart FFI，否则不适用于Dart/Flutter库。')
        elf_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        relro = self.relro()
        if relro == NA:
            severity = INFO
            desc = ('RELRO检查不适用于Flutter/Dart二进制文件')
        elif relro == FULL_RELRO:
            severity = INFO
            desc = (
                '该共享对象已启用完全RELRO。RELRO确保在易受攻击的ELF二进制文件中'
                'GOT不能被覆盖。在完全RELRO中，整个GOT(.got和.got.plt)都被标记为只读。')
        elif relro == PARTIAL_RELRO:
            severity = WARNING
            desc = (
                '该共享对象已启用部分RELRO。RELRO确保在易受攻击的ELF二进制文件中'
                'GOT不能被覆盖。在部分RELRO中，GOT部分的非PLT部分是只读的，'
                '但.got.plt仍然可写。使用选项-z,relro,-z,now启用完全RELRO。')
        else:
            severity = HIGH
            desc = (
                '该共享对象未启用RELRO。整个GOT(.got和.got.plt)都是可写的。'
                '没有这个编译器标志，全局变量上的缓冲区溢出可以覆盖GOT条目。'
                '使用选项-z,relro,-z,now启用完全RELRO，'
                '仅使用-z,relro启用部分RELRO。')
        elf_dict['relocation_readonly'] = {
            'relro': relro,
            'severity': severity,
            'description': desc,
        }
        rpath = self.rpath()
        if rpath:
            severity = HIGH
            desc = (
                '该二进制文件设置了RPATH。在某些情况下，'
                '攻击者可以滥用此功能运行任意库以执行代码和提升权限。'
                '库应该设置RPATH的唯一情况是当它链接到同一包中的私有库时。'
                '移除编译器选项-rpath以删除RPATH。')
            rpt = rpath.rpath
        else:
            severity = INFO
            desc = (
                '该二进制文件未设置运行时搜索路径或RPATH。')
            rpt = rpath
        elf_dict['rpath'] = {
            'rpath': rpt,
            'severity': severity,
            'description': desc,
        }
        runpath = self.runpath()
        if runpath:
            severity = HIGH
            desc = (
                '该二进制文件设置了RUNPATH。在某些情况下，'
                '攻击者可以滥用此功能或修改环境变量以运行任意库，'
                '从而执行代码和提升权限。库应该设置RUNPATH的唯一情况是'
                '当它链接到同一包中的私有库时。移除编译器选项'
                '--enable-new-dtags,-rpath以删除RUNPATH。')
            rnp = runpath.runpath
        else:
            severity = INFO
            desc = (
                '该二进制文件未设置RUNPATH。')
            rnp = runpath
        elf_dict['runpath'] = {
            'runpath': rnp,
            'severity': severity,
            'description': desc,
        }
        fortified_functions = self.fortify()
        if fortified_functions:
            severity = INFO
            desc = ('该二进制文件具有以下强化函数：'
                    f'{fortified_functions}')
        else:
            if self.is_dart():
                severity = INFO
            else:
                severity = WARNING
            desc = ('该二进制文件没有任何强化函数。强化函数'
                    '提供了针对glibc常见不安全函数(如strcpy、gets等)'
                    '的缓冲区溢出检查。使用编译器选项'
                    '-D_FORTIFY_SOURCE=2来强化函数。'
                    '此检查不适用于Dart/Flutter库。')
        elf_dict['fortify'] = {
            'is_fortified': bool(fortified_functions),
            'severity': severity,
            'description': desc,
        }
        is_stripped = self.is_symbols_stripped()
        if is_stripped:
            severity = INFO
            desc = '符号已被剥离。'
        else:
            severity = WARNING
            desc = '符号可用。'
        elf_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return elf_dict

    def is_elf(self, elf_path):
        return lief.is_elf(elf_path)

    def is_nx(self):
        return self.elf.has_nx

    def is_pie(self):
        if self.elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN:
            if self.elf.has(lief.ELF.DynamicEntry.TAG.DEBUG_TAG):
                return 'pie'
            else:
                return 'dso'
        elif self.elf.header.file_type == lief.ELF.Header.FILE_TYPE.REL:
            return 'rel'
        return 'no'

    def is_dart(self):
        dart = ('_kDartVmSnapshotInstructions',
                'Dart_Cleanup')
        if any(i in self.strings() for i in dart):
            return True
        for symbol in dart:
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def has_canary(self):
        if self.is_dart():
            return True
        for symbol in ('__stack_chk_fail',
                       '__intel_security_cookie'):
            try:
                if self.elf.get_symbol(symbol):
                    return True
            except Exception:
                pass
        return False

    def relro(self):
        try:
            gnu_relro = lief.ELF.Segment.TYPE.GNU_RELRO
            bind_now_flag = lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW
            flags_tag = lief.ELF.DynamicEntry.TAG.FLAGS
            flags1_tag = lief.ELF.DynamicEntry.TAG.FLAGS_1
            now_flag = lief.ELF.DynamicEntryFlags.FLAG.NOW

            if self.is_dart():
                return NA

            if not self.elf.get(gnu_relro):
                return NO_RELRO

            flags = self.elf.get(flags_tag)
            bind_now = flags and bind_now_flag in flags

            flags1 = self.elf.get(flags1_tag)
            now = flags1 and now_flag in flags1

            if bind_now or now:
                return FULL_RELRO
            else:
                return PARTIAL_RELRO
        except Exception:
            pass
        return NO_RELRO

    def rpath(self):
        rpath = lief.ELF.DynamicEntry.TAG.RPATH
        return self.elf.get(rpath)

    def runpath(self):
        runpath = lief.ELF.DynamicEntry.TAG.RUNPATH
        return self.elf.get(runpath)

    def is_symbols_stripped(self):
        try:
            for i in self.elf.symtab_symbols:
                if i:
                    return False
            return True
        except Exception:
            try:
                return nm_is_debug_symbol_stripped(
                    self.elf_path)
            except Exception:
                return True

    def fortify(self):
        fortified_funcs = []
        for function in self.elf.symbols:
            if isinstance(function.name, bytes):
                try:
                    function_name = function.name.decode('utf-8')
                except UnicodeDecodeError:
                    function_name = function.name.decode('utf-8', 'replace')
            else:
                function_name = function.name
            if function_name.endswith('_chk'):
                fortified_funcs.append(function.name)
        return fortified_funcs

    def strings(self):
        normalized = set()
        try:
            elf_strings = self.elf.strings
        except Exception:
            elf_strings = None
        if not elf_strings:
            elf_strings = strings_on_binary(self.elf_path)
        for i in elf_strings:
            if isinstance(i, bytes):
                continue
            normalized.add(i)
        return list(normalized)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.elf.symtab_symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
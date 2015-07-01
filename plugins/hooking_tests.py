from collections import defaultdict
import idaapi
import networkx as nx
import sark
import sark.qt


class IDATracker(idaapi.UI_Hooks):
    def __init__(self):
        super(IDATracker, self).__init__()

    def updating_actions(self, ctx=idaapi.action_update_ctx_t()):
        try:
            if ctx.form_type == idaapi.BWN_DISASM:
                self.on_ea(ctx.cur_ea, ctx)
        except NotImplementedError:
            pass

    def on_ea(self, ea, ctx):
        raise NotImplementedError()

    def track(self):
        self.hook()


class LineHighlight(IDATracker):
    def __init__(self):
        super(LineHighlight, self).__init__()
        self.current_ea = None

    def on_ea(self, ea, ctx):
        if self.current_ea is not None:
            sark.Line(self.current_ea).color = None
        sark.Line(ea).color = 0x66EE22
        if self.current_ea != ea:
            self.current_ea = ea


class UnreachableHighlight(IDATracker):
    def on_ea(self, ea, ctx):
        graph = sark.codeblocks.get_nx_graph(ea)
        my_node = sark.codeblocks.get_block_start(ea)
        for node in graph.nodes_iter():
            if nx.has_path(graph, node, my_node) or nx.has_path(graph, my_node, node):
                sark.codeblocks.get_codeblock(node).color = None
            else:
                sark.codeblocks.get_codeblock(node).color = 0x3344DD


class FlowTracker(IDATracker):
    def __init__(self):
        super(FlowTracker, self).__init__()
        self.cur_ea = None
        self.index = 0

    def on_ea(self, ea, ctx):
        if ea == self.cur_ea:
            return

        widget = sark.qt.form_to_widget(ctx.form)
        sark.qt.capture_widget(widget, r"c:\temp\idaflow\idaflow{:08d}.png".format(self.index))
        self.index += 1
        self.cur_ea = ea


class UiHooks(idaapi.UI_Hooks):
    current_ea = None
    current_enum = None

    def updating_actions(self, ctx=idaapi.action_update_ctx_t()):
        if ctx.cur_enum != idaapi.BADNODE:
            UiHooks.current_enum = ctx.cur_enum
            idaapi.msg("{}\n".format(sark.Enum(eid=ctx.cur_enum).name))

        if ctx.form_type not in (idaapi.BWN_DISASM, idaapi.BWN_DUMP):
            return super(UiHooks, self).updating_actions(ctx)

        if ctx.cur_ea != UiHooks.current_ea:
            idaapi.msg("0x{:08X}\n".format(ctx.cur_ea))
            UiHooks.current_ea = ctx.cur_ea

        return super(UiHooks, self).updating_actions(ctx)

    def preprocess(self, *args):
        return super(UiHooks, self).preprocess(*args)

    def postprocess(self, *args):
        return super(UiHooks, self).postprocess(*args)


class IDBHooks(idaapi.IDB_Hooks):
    def enum_renamed(self, *args):
        return super(IDBHooks, self).enum_renamed(*args)

    def enum_member_created(self, *args):
        return super(IDBHooks, self).enum_member_created(*args)

    def enum_member_deleted(self, *args):
        return super(IDBHooks, self).enum_member_deleted(*args)


class HookIDA(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "hooks"
    help = ""
    wanted_name = "Hook"
    wanted_hotkey = ""

    def init(self):
        idaapi.askaddr(1, "123")
        self.ui_hooks = UiHooks()
        self.ui_hooks.hook()
        self.idb_hooks = IDBHooks()
        self.idb_hooks.hook()
        self.flow = FlowTracker()
        self.flow.track()
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HookIDA()

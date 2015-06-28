import idaapi

import sark


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
        self.ui_hooks = UiHooks()
        self.ui_hooks.hook()
        self.idb_hooks = IDBHooks()
        self.idb_hooks.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return HookIDA()

# coding=utf-8

from idaapi import *
from idc import *
from EDRHelper import *
from idautils import *

class EDRHooks(DBG_Hooks):
    
    def user_helper(self):

        self.helper=EDRHelper("nvram_bufget","nvram_get")
        self.file_handle=open("result.txt","a+")
        
    def dbg_bpt(self,tid,ea):

        print "hit on 0x%08x" % ea
       
        
        
        self.dbgstep_into(ea)
        

        key=self.helper.get_arg_value("A1")
        self.file_handle.write(key+"\n")
        self.file_handle.flush()

        idaapi.continue_process()
        
        

    def dbgstep_into(self,ea):
        
        #先把断点禁用才能stp_into
        EnableBpt(ea,0)
        
        step_into()
        #必须用GetDebuggerEvent处理step_into()
        GetDebuggerEvent(WFNE_SUSP , -1)
        EnableBpt(ea,1)

        




debugger=EDRHooks()
debugger.hook()
debugger.user_helper()
'''
AddBpt(0x45fdb4)
AddBpt(0x45fEF0)
AddBpt(0x45ff78)
AddBpt(0x4600A0)
'''
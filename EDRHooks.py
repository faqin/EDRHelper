# coding=utf-8
from idaapi import *
import idc
from EDRHelper import *
class EDRHooks(DBG_Hooks):
    

    def dbg_bpt(self,tid,ea):

        print "hit on 0x%08x" % ea
       
        print type(ea)
        try:
            self.dbgstep_into(ea)
        

            a=EDRHelper()
        

            print a.get_arg_value("A1")
        except Exception,ex:
            print 'except'

        idaapi.continue_process()
        #print  self.get_arg_value("A1")
        

    def dbgstep_into(self,ea):
        
        #先把断点禁用才能stp_into
        EnableBpt(ea,0)
        
        step_into()
        #必须用GetDebuggerEvent处理step_into()
        GetDebuggerEvent(WFNE_SUSP , -1)
        EnableBpt(ea,1)
        




debugger=EDRHooks()
debugger.hook()

AddBpt(0x45fdb4)
AddBpt(0x45fEF0)
AddBpt(0x45ff78)
AddBpt(0x4600A0)

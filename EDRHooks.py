# coding=utf-8

from idaapi import *
import idc

class EDRHooks(DBG_Hooks):
    
    def dbg_bpt(self,tif,ea):

        print "hit on 0x%08x" %ea
        for k,v in self.get_arg_dict.items():
            print "%s=%s" % (k,v)
        return 1
    
    def get_arg_dict(self,arg_name_list=[]):

        
        super.dbg_step_into()

        return {k:self.get_arg_value(k) for k in arg_name_list }
    

    def get_arg_value(self,arg_name):
        regvalue=GetRegValue(arg_name)
        if is_addr(regvalue):
            return self.get_str(regvalue)
        else:
            return regvalue





    def get_str(self,addr):
        
        str=''
        while Byte(addr)!=0:
            str+=chr(Byte(addr))
            addr+=1
        return str


    def is_addr(self,data):
        if data>=idc.MinEA() and data<MaxEA():
            return 1
        else:
            return 0



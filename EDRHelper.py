# coding=utf-8
import idc
import idaapi

class EDRHelper:

    
    def get_func_called_addr(self,func_name=None):

        return func_name and [ func_called_addr for func_called_addr in CodeRefsTo(LocByName(func_name),0) ] or []
    
        

    def get_arg_value(self,arg_name):
        regvalue=idc.GetRegValue(arg_name)
        if self.is_addr(regvalue):
            return self.get_asc_str(regvalue)
        else:
            return regvalue


    def is_addr(self,data):

        if data>=idc.MinEA() and data <=idc.MaxEA():
            return 1
        else:
            return 0
    
    def get_asc_str(self,addr):
        asc_str=''
        while idc.Byte(addr)!=0:
            asc_str+=chr(idc.Byte(addr))
            addr+=1
        return asc_str
    
    




        

# coding=utf-8

from idaapi import *
from idc import *
from idautils import *

class EDRHelper:


    def __init__(self,*tuple_func):
        self.tuple_func=tuple_func
        self.bp()


     
    
    def bp(self):
        func_list=self.get_func_called_addr(self.tuple_func)

        for addr in func_list:
            AddBpt(addr)

    def get_func_called_addr(self,func_name):
        l=[]

        gen_addr=[CodeRefsTo(func_addr,0) for func_addr in (LocByName(func) for func in func_name)]

        for refs in gen_addr:
            for ref in refs:
                l.append(ref)
        return l
                

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





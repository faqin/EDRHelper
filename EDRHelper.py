# coding=utf-8
import idc
import idaapi

class EDRHelper:

    
    def get_func_called_addr(self,func_name=None):
        
        if not func_name:

            return []
        else:

            return [ func_called_addr for func_called_addr in CodeRefsTo(LocByName(func_name),0) ]
    
    
    



        

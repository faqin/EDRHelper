#-*-coding:utf-8-*-
import idc
import idaapi
import idautils

class scan_vulns():

    danger_func_caller={}
    danger_func_addr_list=[]
    danger_func_called_addr_list=[]
    danger_func_called_dict={}
    danger_func_name_list=['gets','strcpy','memcpy','strcat','sprintf','scanf','sscanf',
    'fscanf','vfscanf','vsprintf','vscanf','vsscanf','streadd','strecpy','strtrns','realpath','syslog',
    'getopt','getopt_long','getpass','getchar','fgetc','getc','read','bcopy','fgets','memcpy','snprintf',
    'strccpy','strcadd','strncpy','vsnprintf']

    def __init__(self):
        pass
    

    def scan_danger_func_called(self):

        '''
        扫描危险函数调用地址列表
        参数：无
        返回值：一个字典，例如有指令 0x4001000 call stcpy 则返回 {'0x4001000L':'call strcpy'}
        '''
        '''
        for func_name in self.danger_func_name_list:
            self.danger_func_addr_list.append(idc.LocByName(func_name))
        '''
        #将危险函数名转换为对应的地址列表
        self.danger_func_addr_list.extend([idc.LocByName(func_name) for func_name in self.danger_func_name_list])

        for func_addr in self.danger_func_addr_list:
            for called_addr in idautils.CodeRefsTo(func_addr,0):
                self.danger_func_called_dict[hex(called_addr)]=idc.GetDisasm(called_addr)
        return self

    def get_caller(self):
        
        '''
        for item in self.danger_func_called_dict:
            pass
        '''
        #{  for key in self.danger_func_called_dict.keys()}
        for key,value in self.danger_func_called_dict.items():
            caller_func=idc.GetFunctionName(long(key,16))
            if caller_func not in self.danger_func_caller.keys():
                self.danger_func_caller[caller_func]=[(key,value)]
            else:
                self.danger_func_caller[caller_func].append((key,value))
    

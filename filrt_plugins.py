from idaapi import *
import idc
import idautils
import struct
import binascii
import nampa

class myIdaPlugin(plugin_t):
    flags=0
    wanted_name="my ida filter plugin"
    wanted_hotkey="F1"
    comment="my ida filter plugin"
    help="identify the lib helpfully"
    global sig
    global identified_func
    fpath='E://path//marvel.err'
    if fpath.endswith('.err'):
        sig=nampa.parse_flirt_pat_file(open(fpath,'r'))
    elif fpath.endswith('.sig'):
        sig = nampa.parse_flirt_sig_file(open(fpath, 'r'))
    def init(self):
        msg("Ida plugin init called.\n")
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        identified_func={}
        for func_ea in idautils.Functions():
            #get the function name
            function_name=idc.GetFunctionName(func_ea)
            print function_name
            if not function_name.startswith("sub_"):
                continue
            func_byteStr32=""
            func_str=idc.GetManyBytes(func_ea, 32)
            for fb in func_str:
                byte_str=binascii.b2a_hex(fb)
                func_byteStr32+=byte_str
            print func_byteStr32
            match_result=nampa.match_function(sig,func_byteStr32)
            print match_result
            if match_result[0]:
                function_names=''
                for function_name in match_result[1]:
                    if len(function_names)==0:
                        function_names=function_name
                        continue
                    function_names=function_names+"_"+function_name
                    #set the function name
                num=0
                print identified_func
                if identified_func.has_key(function_names):
                    num=identified_func[function_names]
                    num+=1
                    identified_func[function_names]=num
                else:
                    identified_func[function_names]=num
                function_names=function_names+str(num)
                idc.MakeName(func_ea,function_names)
        warning("Ida plugin run(%d) called.\n"%arg)
def PLUGIN_ENTRY():
    return myIdaPlugin()

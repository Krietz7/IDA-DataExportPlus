import os

import idc
import idaapi
import ida_ida
from ida_kernwin import add_hotkey
from ida_bytes import get_flags

VERSION = "1.1"

class DEP_Conversion():

    @classmethod
    def get_list(self):
        Data_base_list = {"Hexadecimal":16,"Decimal":10,"Octal":8,"Binary":2,}
        Data_type_list = {"Byte":1,"Word":2,"Dword":3,"Qword":4,"String literal":5,"Assembly Code":6,"Raw bytes":7}
        Data_exported_format_list = {"String":0,"C variable":1,"Python variable":2}
        return (Data_base_list,Data_type_list,Data_exported_format_list)

    # data(bytes) big_endian(Bool) data_type(int) base(int) delimiter(str) prefix(str) suffix(str)
    def __init__(self,address, data_bytes, data_type_key = 1, export_type_key = 0,big_endian = False, base_key = 0, delimiter = " ",prefix = "",suffix = "",keep_comments = False, keep_names = False):
        self.address = address
        self.Data_base_list = self.get_list()[0]
        self.Data_type_list = self.get_list()[1]
        self.data_bytes = data_bytes
        self.export_type_key = export_type_key
        self.big_endian = big_endian
        self.base_key = base_key
        self.data_type_key = data_type_key 
        self.delimiter = delimiter
        self.prefix = prefix
        self.suffix = suffix
        self.keep_comments = keep_comments
        self.keep_names = keep_names

    @classmethod
    def dict_key_to_list(self,dictionary):
        t = list(dictionary.items())
        key = [i[0] for i in t]
        return key

    @classmethod
    def dict_value_to_list(self,dictionary):
        t = list(dictionary.items())
        value = [i[1] for i in t]
        return value


    def activate(self):
        self.base = self.dict_value_to_list(self.Data_base_list)[self.base_key]
        self.type = self.dict_key_to_list(self.Data_type_list)[self.data_type_key]

        output = ""
        if(self.type in ['Byte','Word','Dword','Qword']):
            output = self.NumberConversion()

        elif(self.type == "String literal"):
            output = self.StringLiteralConversion()

        elif(self.type == "Assembly Code"):
            output = self.AssemblyCodeConversion()
        elif(self.type == "Raw bytes"):
            return "Cannot preview binary data"

        # String
        if(self.export_type_key == 0):
            return output

        # C variable
        elif(self.export_type_key == 1):
            if(self.type in ['Byte','Word','Dword','Qword']):
                C_type = {"Byte":"unsigned char","Word":"unsigned short","Dword":"unsigned int","Qword":"unsigned long long int"}[self.type]
                return C_type+" IDA_"+ hex(self.address)[2:] + "[] = {" + output + "};"

            elif(self.type == "String literal"):
                return "unsigned char IDA_"+ hex(self.address)[2:] + "[] = \"" + output + "\";"

            elif(self.type == "Assembly Code"):
                output = '\\n\"\n\"'.join([line for line in output.splitlines()])[:-1]
                return "std:string IDA_"+ hex(self.address)[2:] + " = \"" + output + "\";"

            return None


        # Python variable
        elif(self.export_type_key == 2):
            if(self.type in ['Byte','Word','Dword','Qword']):
                return "IDA_" + hex(self.address)[2:] + " = [" +output + "]"

            elif(self.type == "String literal"):
                return "IDA_" + hex(self.address)[2:] + " = b\'" + output + '\''

            elif(self.type == "Assembly Code"):
                return "IDA_" + hex(self.address)[2:] + " = \'\'\'" + output + '\'\'\''



        return None

    def convert_base(self, number, target_base):
        digit_map = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        result = ''
        while number:
            remainder = number % target_base
            result = digit_map[remainder] + result
            number //= target_base

        if(result == ''):
            return "0"
        return result

    # base on Byte/Word/Dword/Qword convert byte stream to number
    # parameter: base big_endian prefix suffix
    def NumberConversion(self):
        Number_array = []
        type_len_list = {"Byte":1,"Word":2,"Dword":4,"Qword":8}
        Number_len = type_len_list[self.type]
        if(not self.big_endian):
            for i in range(0, len(self.data_bytes), Number_len):
                Number_array.append(int.from_bytes(self.data_bytes[i:i+Number_len],byteorder='little'))
        else:
            for i in range(0, len(self.data_bytes), Number_len):
                Number_array.append(int.from_bytes(self.data_bytes[i:i+Number_len],byteorder='big'))
        if(self.base > 0 and self.base < 36):
            return self.delimiter.join("{0}{1}{2}".format(self.prefix,str(self.convert_base(i,self.base)),self.suffix) for i in Number_array)
        return None

    def StringLiteralConversion(self):
        return str(self.data_bytes)[2:-1]


    def AssemblyCodeConversion(self):
        assembly_code_start = self.address
        assembly_code_end = self.address + len(self.data_bytes)

        output = ""
        i = assembly_code_start
        if(assembly_code_start > ida_ida.inf_get_max_ea() or assembly_code_start < ida_ida.inf_get_min_ea()):
            return ""
        while i < assembly_code_end:
            if(self.keep_names):
                addr_name = idc.get_name(i)
                if addr_name:
                    output += "\n" + addr_name + ":\n"
            if(self.keep_comments):
                output += idc.generate_disasm_line(i,0)
            else:
                output += idc.generate_disasm_line(i,0).split(";")[0]
            output += "\n"

            i = idc.find_code(i, 1)
        return output


class DEP_Form(idaapi.Form):
    # idaapi information
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    # list
    Data_base_list,Data_type_list,Data_exported_format_list = DEP_Conversion.get_list()

    def __init__(self,select_addr,select_len):
        self.export_address = select_addr
        self.export_address_len = select_len
        self.Data_bytes = b""
        self.export_data_type_key = 0


        # Format Options
        self.export_big_endian = False
        self.export_base_key = 0
        self.export_delimiter = ","
        self.export_prefix = "0x"
        self.export_suffix = ""
        self.export_type_key = 0
        self.export_keep_comments = False
        self.export_keep_names = False

        self.export_data = None
        self.export_file_path = os.getcwd() + "\\export_results.txt"


        data_type_flag = get_flags(self.export_address)
        checks = [
            (idc.is_byte, 0),
            (idc.is_word, 1),
            (idc.is_dword, 2),
            (idc.is_qword, 3),
            (idc.is_strlit, 4),
            (idc.is_code, 5)
        ]
        self.export_data_type_key = next((key for func, key in checks if func(data_type_flag)), 0)

        super(DEP_Form, self).__init__(

            r'''STARTITEM 0
BUTTON YES* Export
Export Plus: Export Data
            
            {FormChangeCb}
            <Selected address :{_address}>
            <Selected Length  :{_length}>
            <~Selected Data~    :{_select_data}>
            < Data Type       :{_data_type}>
            < Export As       :{_export_type}>

            Export Format:
            <##-   Endianness :{_endianness}>
            <##-   Base       :{_base}>
            <##-   Delimiter  :{_delimiter}>
            <##-   Prefix     :{_prefix}>
            <##-   Suffix     :{_suffix}>

            <##-   Keep Comments:{_keep_comments}>
            <##-   Keep Names   :{_keep_names}>
            <~Export Window~: {_export_text}>
            <Export File Path: {_export_file_path}>
            ''',
            {
                "FormChangeCb": self.FormChangeCb(self.OnFormChange),

                "_address": self.NumericInput(value = self.export_address, tp=self.FT_ADDR, swidth=30),
                "_length": self.NumericInput(value = self.export_address_len, swidth = 30),
                "_select_data": self.StringInput(value = "",swidth = 30),                
                "_data_type": self.DropdownListControl(items = list(self.Data_type_list.keys()),selval = self.export_data_type_key),
                "_export_type": self.DropdownListControl(items =list(self.Data_exported_format_list.keys())),

                "_endianness": self.DropdownListControl(items = ["Little-endian","Big-endian"]),
                "_base": self.DropdownListControl(items = list(self.Data_base_list.keys())),
                "_delimiter": self.StringInput(value = self.export_delimiter,swidth = 30),
                "_prefix": self.StringInput(value = self.export_prefix,swidth = 30),
                "_suffix": self.StringInput(value = self.export_suffix,swidth = 30),
                "_keep_comments": self.DropdownListControl(items = ["False", "True"]),
                "_keep_names": self.DropdownListControl(items = ["False", "True"]),


                "_export_text": self.MultiLineTextControl(text = "",swidth = 48),
                "_export_file_path": self.FileInput(value = self.export_file_path, save = True,swidth = 30),
            }

        )
        self.Compile()

    def OnFormChange(self,fid):
        # initialization
        data_str = ""
        if(fid == -1):
            self.EnableField(self._select_data,False)
            try:
                input_export_address = self.GetControlValue(self._address)
                input_export_address_len = self.GetControlValue(self._length)

                self.min_ea = ida_ida.inf_get_min_ea()
                self.max_ea = ida_ida.inf_get_max_ea()

                if(self.min_ea < input_export_address and self.max_ea > input_export_address and self.max_ea > input_export_address + input_export_address_len):
                    self.Data_bytes,data_str =self.GetEAData(input_export_address,input_export_address_len)
                    self.SetControlValue(self._select_data,data_str)

                    self.export_address = input_export_address
                    self.export_address_len = input_export_address_len
            except:
                return 1

        # change Selected information
        elif(fid == self._address.id or fid == self._length.id):
            try:
                input_export_address = self.GetControlValue(self._address)
                input_export_address_len = self.GetControlValue(self._length)
    
                self.min_ea = ida_ida.inf_get_min_ea()
                self.max_ea = ida_ida.inf_get_max_ea()

                if(self.min_ea < input_export_address and self.max_ea > input_export_address and self.max_ea > input_export_address + input_export_address_len):
                    self.Data_bytes,data_str =self.GetEAData(input_export_address,input_export_address_len)
                    self.SetControlValue(self._select_data,data_str)

                    self.export_address = input_export_address
                    self.export_address_len = input_export_address_len
            except:
                return 1

        # change export format or export type
        if(fid in [-1, self._data_type.id, self._export_type.id]):
            self.export_data_type_key = self.GetControlValue(self._data_type)
            self.export_type_key = self.GetControlValue(self._export_type)

            # change Form Controls property

            # Byte
            if(self.export_data_type_key == 0):
                self.ShowField(self._export_type,True)

                self.ShowField(self._endianness,False)
                self.ShowField(self._base,True)
                self.ShowField(self._delimiter,True)
                self.ShowField(self._prefix,True)
                self.ShowField(self._suffix,True)
                self.ShowField(self._keep_comments,False)
                self.ShowField(self._keep_names,False)


                # export as string
                if(self.export_type_key == 0):
                    self.EnableField(self._delimiter,True)
                    self.EnableField(self._prefix,True)
                    self.EnableField(self._suffix,True)


            # Word,Dword,Qword
            elif(self.export_data_type_key in [1,2,3]):
                self.ShowField(self._export_type,True)

                self.ShowField(self._endianness,True)
                self.ShowField(self._base,True)
                self.ShowField(self._delimiter,True)
                self.ShowField(self._prefix,True)
                self.ShowField(self._suffix,True)
                self.ShowField(self._keep_comments,False)
                self.ShowField(self._keep_names,False)

                # export as string
                if(self.export_type_key == 0):
                    self.EnableField(self._endianness,True)
                    self.EnableField(self._delimiter,True)
                    self.EnableField(self._prefix,True)
                    self.EnableField(self._suffix,True)

            # String literal
            elif(self.export_data_type_key == 4):
                self.ShowField(self._export_type,True)

                self.ShowField(self._endianness,False)
                self.ShowField(self._base,False)
                self.ShowField(self._delimiter,False)
                self.ShowField(self._prefix,False)
                self.ShowField(self._suffix,False)
                self.ShowField(self._keep_comments,False)
                self.ShowField(self._keep_names,False)

            # Assembly Code
            elif(self.export_data_type_key == 5):
                self.ShowField(self._export_type,True)

                self.ShowField(self._endianness,False)
                self.ShowField(self._base,False)
                self.ShowField(self._delimiter,False)
                self.ShowField(self._prefix,False)
                self.ShowField(self._suffix,False)
                self.ShowField(self._keep_comments,True)
                self.ShowField(self._keep_names,True)

            # Raw bytes
            elif(self.export_data_type_key == 6):
                self.ShowField(self._export_type,False)

                self.ShowField(self._endianness,False)
                self.ShowField(self._base,False)
                self.ShowField(self._delimiter,False)
                self.ShowField(self._prefix,False)
                self.ShowField(self._suffix,False)
                self.ShowField(self._keep_comments,False)
                self.ShowField(self._keep_names,False)







            # export as string
            if(self.export_type_key == 0):
                pass

            # export as C varible
            elif(self.export_type_key == 1):
                self.EnableField(self._delimiter,False)
                self.EnableField(self._prefix,False)
                self.EnableField(self._suffix,False)


            # export as Python varible
            elif(self.export_type_key == 2):
                self.EnableField(self._delimiter,False)
                self.EnableField(self._prefix,False)
                self.EnableField(self._suffix,False)

            # change default value
            self.SetControlsDefaultValue()





        elif(fid in [self._endianness.id,self._base.id,self._delimiter.id,self._prefix.id,self._suffix.id,self._keep_comments.id,self._keep_names.id]):
            self.export_big_endian = self.GetControlValue(self._endianness)
            self.export_base_key = self.GetControlValue(self._base)
            self.export_delimiter = self.GetControlValue(self._delimiter)
            self.export_prefix = self.GetControlValue(self._prefix)
            self.export_suffix = self.GetControlValue(self._suffix)
            self.export_keep_comments = {0:False,1:True}[self.GetControlValue(self._keep_comments)]
            self.export_keep_names = {0:False,1:True}[self.GetControlValue(self._keep_names)]


            if(fid == self._base.id):
                self.SetControlsDefaultValue()


        elif(fid == self._export_file_path.id):
            self.export_file_path = self.GetControlValue(self._export_file_path)




        # refresh MultiLineTextControl
        self.RefreshExportWindow()

        return 1


    def GetEAData(self,address,length):
        data_byte = idc.get_bytes(address,length)
        data_str = ' '.join([f"{i:02X}" for i in bytearray(data_byte)])

        return data_byte,data_str.strip()


    def RefreshExportWindow(self):
        t = DEP_Conversion(address = self.export_address, data_bytes = self.Data_bytes,
                           data_type_key = self.export_data_type_key,
                           export_type_key = self.export_type_key,
                           big_endian = self.export_big_endian,
                           base_key = self.export_base_key,
                           delimiter = self.export_delimiter,
                           prefix = self.export_prefix,
                           suffix = self.export_suffix, 
                           keep_comments = self.export_keep_comments,
                           keep_names = self.export_keep_names)
        self.export_data = t.activate()
        self.SetControlValue(self._export_text,  idaapi.textctrl_info_t(text = self.export_data, flags = 32, tabsize = 0))


    def SetControlsDefaultValue(self):
        if(self.export_data_type_key in [0,1,2,3]):

            Prefix_list = {0:"0x",1:"",2:"0o",3:"0b"}
            self.export_prefix = Prefix_list[self.export_base_key]
            self.SetControlValue(self._prefix,self.export_prefix)

            if(self.export_type_key == 1):
                self.export_delimiter = ", "
                self.SetControlValue(self._delimiter,", ")
                self.export_suffix = ""
                self.SetControlValue(self._suffix,"")
                # export as C array
                if(self.export_data_type_key == 3):
                    self.export_suffix = "ULL"
                    self.SetControlValue(self._suffix,"ULL")
                if(self.export_base_key == 2):
                    self.export_prefix = "0"
                    self.SetControlValue(self._prefix,self.export_prefix)


            if(self.export_type_key == 2):
                self.export_delimiter = ", "
                self.SetControlValue(self._delimiter,", ")
                self.export_suffix = ""
                self.SetControlValue(self._suffix,"")
                # export as Python array



class DataExportPlus(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Export Data"
    help = ""
    wanted_name = "Data Export Plus"
    version = VERSION

    def init(self):
        print("=" * 80)
        print("Start Data Export Plus plugin")

        idc.del_idc_hotkey("Shift+E")
        add_hotkey("Shift-E", self.hotkeystart)

        return idaapi.PLUGIN_KEEP

    def term(self):
        return

    def hotkeystart(self):
        self.run(None)

    def run(self, args):
        ea_addr,ea_item_size = self.GetEAItem()
        form = DEP_Form(ea_addr,ea_item_size)
        IsExport = form.Execute()


        if(IsExport):
            if(os.path.exists(form.export_file_path)):
                k = idc.ask_yn(1,"Export file already exists, Do you want to overwrite it?")
                if(k == -1 or k == 0):
                    form.Free()
                    return 1
            try:
                if(form.export_data_type_key == 6):
                    with open(form.export_file_path, "wb") as file_handle:
                        file_handle.write(form.Data_bytes)
                else:
                    with open(form.export_file_path, "w", encoding="utf-8") as file_handle:
                        file_handle.write(form.export_data)

                print("Stored export results in",form.export_file_path)

            except:
                idc.warning("Export file failed")

        form.Free()
        return 1


    def GetEAItem(self):
        selection, ea_addr, ea_addr_end = idaapi.read_range_selection(None)

        if (selection):
            ea_item_size = ea_addr_end - ea_addr
        else:
            ea_addr = idc.get_screen_ea()
            ea_item_size = idc.get_item_size(idc.get_screen_ea())

        return ea_addr,ea_item_size




def PLUGIN_ENTRY():
    return DataExportPlus()

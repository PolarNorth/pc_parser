import os.path
import json
import binascii
import parse_bytecode
import pprint
import sys

class pc_parser:
    """.pc file parser
    Can save data in .json and in readable format in .txt
    """
    file_path = ''
    pc_dir = ''
    output_dir = ''
    show_record_data = False
    show_rest_data = False
    show_method_code = False
    save_json = True
    save_in_txt = True
    show_debug = False

    def __init__(self, pc_dir, filename, output):
        # self.pc_dir = os.path.abspath(os.path.dirname(__file__))
        # self.pc_dir = os.path.join(self.pc_dir, "/pc")
        self.set_dir(pc_dir)
        self.set_file(filename)
        self.set_output_dir(output)
    
    def set_file(self, filename):
        self.file_path = os.path.join(self.pc_dir, filename)

    def set_dir(self, dir):
        self.pc_dir = dir
    
    def set_output_dir(self, dir):
        self.output_dir = dir

    def parse(self):
        result = {
            'class_description' : {
                'info' : None,
                'fields' : {},
                'IP_to_ln' : None
            },
            'methods' : {}
        }
        _phfr = 'phfr:'
        data = ''

        with open(self.file_path, 'rb') as f:
            idx = 0
            #data = f.readline()
            data = f.read()

            while (idx < len(data)):
                s = data[idx:idx + 5].decode('utf-8')
                # s = str(data[idx:idx + 5])
                idx += 5
                #print(s + ' ' + str(type(s)))
                rest = ''

                if str(s) == _phfr:
                    rec_type, idx = self.read_int8(data, idx)
                    print('+ record type: ' + str(chr(rec_type)))
                    rec_length, idx = self.read_int32(data, idx)
                    print('+ record length: ' + str(rec_length))
                    rec_data = data[idx: idx + rec_length]
                    if self.show_record_data:
                        print('+ record data: ' + str(rec_data))

                    idx = idx + rec_length
                    if (rec_type == ord('C')):
                        info, rest = self.class_handler(rec_data)
                        result['class_description']['info'] = info
                    elif (rec_type == ord('M')):
                        info, rest = self.method_handler(rec_data)
                        if info['name'] in result['methods'].keys():
                            result['methods'][info['name']].update(info)
                        else:
                            result['methods'][info['name']] = info
                    elif (rec_type == ord('S')):
                        info, rest = self.method_signature_handler(rec_data)
                        if info['name'] in result['methods'].keys():
                            result['methods'][info['name']].update(info)
                        else:
                            result['methods'][info['name']] = info
                    elif (rec_type == ord('l')):
                        info, rest = self.ip2lnm_handler(rec_data)
                        result['class_description']['IP_to_ln'] = info
                    elif (rec_type == ord('f')):
                        info, rest = self.field_handler(rec_data)
                        result['class_description']['fields'][info['name']] = info
                    else:
                        print(' ***ERROR: Unknown signature: ' + chr(rec_type) + '(' + str(rec_type) + ')***')
                    
                    if self.show_rest_data:
                        print('Rest data: ' + str(rest))
                    
                    # print('\n') #bug : why it executes twice???

                    if rest is not None and data is not None:
                        data = rest + data
                else:
                    print('+ WARNING: Cannot find the signature! string: ' + str(s))
            
            if self.save_json:
                self.store_in_json(**result)
            if self.save_in_txt:
                self.store_in_txt(**result)
            
    
    def field_handler(self, data):
        """Reads an information about field from the data
        """
        idx_loc = 0
        field_name, idx_loc = self.read_string(data, idx_loc)
        field_ordinal, idx_loc = self.read_int32(data, idx_loc)
        field_type, idx_loc = self.read_phantom_type(data, idx_loc)
        if self.show_debug:
            print('= Field:')
            print('Field name: ' + str(field_name))
            print('Ordinal: ' + str(field_ordinal))
            print(' - is container: ' + str(field_type[0]))
            print(' - class name: ' + str(field_type[1]))
            print(' - contained class: ' + str(field_type[2]))
        rest = data[idx_loc:]
        return {'name' : field_name, 'ordinal' : field_ordinal, 'type' : field_type}, rest

    def method_signature_handler(self, data):
        """Reads an information about method from the data
        """
        idx_loc = 0
        method_name, idx_loc = self.read_string(data, idx_loc)
        ordinal, idx_loc = self.read_int32(data, idx_loc)
        n, idx_loc = self.read_int32(data, idx_loc)
        constructor, idx_loc = self.read_int32(data, idx_loc) 
        return_type, idx_loc = self.read_phantom_type(data, idx_loc)
        if self.show_debug:
            print('= Method signature:')
            print('Method name: ' + str(method_name))
            print('Ordinal: ' + str(ordinal))
            print('Amount of arguments: ' + str(n))
            print('Constructor: ' + str(constructor))
            print('Return type:')
            print(' - is container: ' + str(return_type[0]))
            print(' - class name: ' + str(return_type[1]))
            print(' - contained class: ' + str(return_type[2]))
        args = []
        for arg_id in range(0,n):
            arg_name, idx_loc = self.read_string(data, idx_loc)
            arg_type, idx_loc = self.read_phantom_type(data, idx_loc)
            args.append((arg_name, arg_type))
            if self.show_debug:
                print('arg # ' + str(arg_id) + ': ' + str(arg_name))
                print(' - is container: ' + str(arg_type[0]))
                print(' - class name: ' + str(arg_type[1]))
                print(' - contained class: ' + str(arg_type[2]))
        rest = data[idx_loc:]
        # if self.show_rest_data:
        #     print('rest: ' + str(rest))
        # print(str(data))
        # s = ''
        # for x in data:
        #     s += str(x) + ' '
        # print(s)
        return {'name' : method_name, 'ordinal' : ordinal, 'args number' : n,
                'constructor' : constructor, 'return type' : return_type,
                'arguments' : args}, rest

    def class_handler(self, data):
            """Reads an information about field from the data
            """
            idx_loc = 0
            cls_name, idx_loc = self.read_string(data, idx_loc)
            fields_cnt, idx_loc = self.read_int32(data, idx_loc)
            methods_cnt, idx_loc = self.read_int32(data, idx_loc)
            base_cls_name, idx_loc = self.read_string(data, idx_loc)
            compile_date, idx_loc = self.read_string(data, idx_loc)
            if self.show_debug:
                print('= Class:')
                print('Class name: ' + str(cls_name))
                print('Fields #: ' + str(fields_cnt))
                print('Methods #: ' + str(methods_cnt))
                print('Base class name: ' + base_cls_name)
                print("Compile date and tim: " + compile_date)
            rest_data = data[idx_loc:]
            if self.show_rest_data:
                print("Rest data: " + str(rest_data))
            return {'name' : cls_name, 'fields number' : fields_cnt,
                    'methods number' : methods_cnt, 'base class' : base_cls_name,
                    'compile date' : compile_date}, rest_data
    
    def method_handler(self, data):
        """Reads an method's bytecode from the data
        """
        idx_loc = 0
        method_name, idx_loc = self.read_string(data, idx_loc)
        ordinal, idx_loc = self.read_int32(data, idx_loc)
        code = data[idx_loc:len(data)-10]   #TODO : Parse code
        bp = parse_bytecode.bytecode_parser()
        parsed_code = bp.parse(code)
        rest = data[len(data)-10:]
        if self.show_debug:
            print('= Method:')
            print('Method name: ' + str(method_name))
            print('Ordinal: ' + str(ordinal))
        if self.show_method_code:
            if self.show_debug:
                print("Method's code: ")
                print(str(code))
                s = ''
                for x in code:
                    s += str(hex(x)) + ' '
                print(s)
            return {'name' : method_name, 'ordinal' : ordinal, 'code_raw' : str(code),
            'code' : parsed_code}, rest
        return {'name' : method_name, 'ordinal' : ordinal, 'code' : parsed_code}, rest
        
    def ip2lnm_handler(self, data):
        """Reads a list of IP addresses and line numbers from the data
        """
        idx_loc = 0
        ip_ln = []
        rest_len = 0
        if len(data) % 8 is not 0:
            rest_len = 10
        while (idx_loc + 8 <= len(data)-rest_len):   #While we can read 2 int32
            ip, idx_loc = self.read_int32(data, idx_loc)
            line_number, idx_loc = self.read_int32(data, idx_loc)
            ip_ln.append((ip, line_number))
            if self.show_debug:
                print("ip - ln: " + str(ip) + ' - ' + str(line_number))
        rest = data[len(data)-rest_len:]
        return ip_ln, rest

    def store_in_json(self, **data):
        """Saves data into .json file
        """
        filename = data['class_description']['info']['name'] + '.json'
        with open(self.output_dir + filename, 'w') as f:
            json.dump(data, f, indent=4)
    
    def store_in_txt(self, **data):
        """Saves data in several .txt files
        cls_... .txt for classes
        mth_... .txt for methods
        """
        cls_file = 'cls_' + data['class_description']['info']['name'] + '.txt'
        with open(self.output_dir + cls_file, 'w') as f:
            for k,v in data['class_description']['info'].items():
                f.write(str(k) + ': ' + str(v) + '\n')
            f.write('IP addresses to line numbers:\n')
            if data['class_description']['IP_to_ln'] is not None:
                for pair in data['class_description']['IP_to_ln']:
                    f.write(hex(pair[0]) + ' -> ' + hex(pair[1]) + '\n')

        for k,v in data['methods'].items():
            mth_file = 'mth_' + data['class_description']['info']['name'] + '.' + k + '.txt'
            code = None
            with open(self.output_dir + mth_file, 'w') as f:
                for pair in v.items():
                    if (pair[0] is 'code'):
                        code = pair[1]
                        continue
                    f.write(pair[0] + ': ' + str(pair[1]) + '\n')          
                if (code is not None):
                    f.write('code:\n\n')
                    for inst in code:
                        if len(inst) is 2:
                            opcode = inst[0]
                            args = inst[1]
                            f.write(opcode + ' ')
                            for arg in args:
                                f.write(str(arg) + ' ')
                            f.write('\n')
                        else:
                            f.write(inst + '\n')
                else:
                    f.write('***ERROR : No code for this method!***')

    def bytes_to_int(self, b):
        """Converts bytes to int
        """
        res = 0
        for x in b:
            res = res << 8
            res += int(x)
            #print('temp: ' + str(res))
        return res

    def read_string(self, data, idx):
        """Reads string from data
        Reads the length first, then string
        """
        length = self.bytes_to_int(data[idx:idx+4])
        idx += 4
        result = str(data[idx:idx + length])
        idx += length
        #cut b''
        result = result[2:len(result)-1]
        return (result, idx)

    def read_int32(self, data, idx):
        """Reads 32-bit integer
        """
        result = self.bytes_to_int(data[idx:idx+4])
        idx += 4
        return result, idx

    def read_int8(self, data, idx):
        """Reads 8-bit integer
        """
        result = self.bytes_to_int(data[idx:idx+1])
        idx += 1
        return result, idx

    def read_phantom_type(self, data, idx):
        """Reads information about phantom type
        """
        is_container, idx = self.read_int32(data, idx)
        main_class, idx = self.read_string(data, idx)
        contained_class, idx = self.read_string(data, idx)
        return (is_container, main_class, contained_class), idx


# p = pc_parser('plc_test/pc', 'testing.branching.pc', 'parsed/')
# p.parse()

if len(sys.argv)-1 is not 3:
    print('***ERROR: wrong number of arguments! given ' + str(len(sys.argv)-1) + '. 3 required***')
    print(sys.argv)

p = pc_parser(sys.argv[1], sys.argv[2], sys.argv[3])
p.parse()
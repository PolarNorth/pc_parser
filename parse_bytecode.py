import os.path
import json

class bytecode_parser:
    """Class for phantom virtual machine bytecode parsing
    """

    show_debug = False

    def __init__(self):
        """Constructor
        initializes dictionary with instructions with specific arguments 
        """
        self._int8 = self.read_int8
        self._int32 = self.read_int32
        self._int64 = self.read_int64
        self._str = self.read_string
        self._ref = self.read_int32

        self.instruction_arguments = {
            'opcode_jmp' : [self._ref],
            'opcode_djnz' : [self._ref],
            'opcode_jz' : [self._ref],
            'opcode_const_pool' : [self._int32],
            'opcode_summon_by_name' : [self._str],  #.str
            'opcode_push_catcher' : [self._ref],
            'opcode_static_invoke' : [self._int32 , self._int32]
        }

    def parse(self, data):
        """Parsing function
        Data should be represented in bytes
        """
        result = []
        if self.show_debug:
            print(str(data))

        s = '' 
        data_bytes = []
        # with open('output.txt', 'w') as f:
        #     f.write(str(data.decode('utf-8', 'ignore')))
        #     f.write('\n\n')
        for x in data:
            s += ' ' + str(hex(x))[2:]
            data_bytes.append(str(hex(x))[2:])
        # f.write(s)

        opcodes = {}
        with open('opcodes.json', 'r') as js:
            opcodes = json.load(js)

        # f.write('\n\n\n')

        unexpected = ''
        idx = 0
        while idx < len(data):
            x = data[idx]
            key = str(x)
            if key in opcodes.keys():
                inst = opcodes[key]
                idx += 1
                # print(inst)
                # f.write(inst + '   ')
                args = []
                if inst in self.instruction_arguments.keys():
                    for x in self.instruction_arguments[inst]:
                        arg, idx = x(data, idx)
                        args.append(arg)
                elif inst.startswith('opcode_call_'):
                    method_index = -1
                    params_num = -1
                    if inst.endswith('8bit'):
                        method_index, idx = self.read_int8(data, idx)
                        params_num, idx = self.read_int32(data, idx)
                    elif inst.endswith('32bit'):
                        method_index, idx = self.read_int32(data, idx)
                        params_num, idx = self.read_int32(data, idx)
                    else:
                        method_index = int(inst[len(inst)-2:])
                        params_num, idx = self.read_int8(data, idx)
                    if method_index < 0 or params_num < 0:
                        print(' ***WARNING: Wrong call!*** ') 
                        # f.write(' ***WARNING: Wrong call!*** \n')
                    args = [method_index, params_num]
                elif inst.endswith('_bin'):
                    arg_string, idx = self.read_string(data, idx)
                    args.append(arg_string)
                elif inst.endswith('_8bit') or inst.endswith('8'):
                    arg_num, idx = self.read_int8(data, idx)
                    args.append(hex(arg_num))
                elif inst.endswith('_32bit') or inst.endswith('32'):
                    arg_num, idx = self.read_int32(data, idx)
                    args.append(hex(arg_num))
                elif inst.endswith('_64bit') or inst.endswith('64'):
                    arg_num, idx = self.read_int64(data, idx)
                    args.append(hex(arg_num))
                elif inst == 'opcode_switch':
                    # print(' ***WARNING: Cannot read opcode_switch arguments!*** ')
                    # f.write(' ***WARNING: Cannot read opcode_switch arguments!*** \n')
                    table_size, idx = self.read_int32(data, idx)
                    shift, idx = self.read_int32(data, idx)
                    divisor, idx = self.read_int32(data, idx)
                    refs = []
                    for i in range(0, table_size):
                        ref, idx = self.read_int32(data, idx)
                        refs.append(ref)
                    args.append(table_size, shift, divisor, refs)
                elif inst == 'opcode_debug':
                    debug_type, idx = self.read_int8(data, idx)
                    info = ''
                    if bin(debug_type)[2] == '1':   #if we have string after type
                        info, idx = self.read_string(data, idx)
                    args.append(debug_type, info)
                if args != []:
                    for i, arg in enumerate(args):
                        if type(arg) is int:
                            args[i] = hex(arg)
                    if self.show_debug:
                        print(inst + ' ' + str(args))
                    result.append((inst, args))
                    # f.write(str(args))
                else:
                    if self.show_debug:
                        print(inst)
                    result.append((inst, []))
                # f.write('\n')
            else:
                unexpected += str(x) + ' '
                idx += 1
                print(' ***WARNING: Unexpected byte to read!***')
                result.append((' ***WARNING: Unexpected byte to read!***'))
                # f.write(' ***WARNING: Unexpected byte to read!*** \n')
        if (len(unexpected) > 0):
            result.append(('UNEXPECTED', unexpected))
            print ('***UNEXPECTED: ' + unexpected + '***')
            # f.write('\n***UNEXPECTED: ' + unexpected + '***')
        if self.show_debug:
            print(result)
        return result


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
        return (result, idx)

    def read_int32(self, data, idx):
        """Reads 32-bit integer
        """
        result = self.bytes_to_int(data[idx:idx+4])
        idx += 4
        return result, idx

    def read_int64(self, data, idx):
        """Reads 64-bit integer
        """
        result = self.bytes_to_int(data[idx:idx+8])
        idx += 8
        return result, idx
    
    def read_int8(self, data, idx):
        """Reads 8-bit integer
        """
        result = self.bytes_to_int(data[idx:idx+1])
        idx += 1
        return result, idx


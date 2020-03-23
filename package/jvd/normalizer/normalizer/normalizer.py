import json

# ARCHITECTURES
ARCHITECTURE_METAPC = "ARCHITECTURE_METAPC"
ARCHITECTURE_ARM = "ARCHITECTURE_ARM"
ARCHITECTURE_MC68 = "ARCHITECTURE_MC68"
ARCHITECTURE_PPC = "ARCHITECTURE_PPC"
ARCHITECTURE_TMS320C6 = "ARCHITECTURE_TMS320C6"

architectures = [ARCHITECTURE_METAPC, ARCHITECTURE_ARM, ARCHITECTURE_MC68, ARCHITECTURE_PPC, ARCHITECTURE_TMS320C6]

NORM_UNIDF = "UNI" # used if not recognised

# NORMALIZATION TYPES
NORM_CATEGORY = "CATEGORY"
NORM_LENGTH = "LENGTH"
NORM_BOTH = "BOTH"

# JSON STRINGS
JSON_ARCHITECTURE_PATH = "Kam1n0-Architecture"
JSON_OPERATIONS_PATH = "operations"
JSON_OPERATION_JUMPS_PATH = "operationJmps"
JSON_OPERATION_PATH = "operation"
JSON_IDENTIFIER_KEY = "_identifier"
JSON_SUFFIXGROUP_KEY = "suffixGroup"
JSON_SUFFIXGROUPS_PATH = "suffixGroups"
JSON_SUFFIX_KEY = "suffix"
JSON_REGISTER_PATH1 = "registers"
JSON_REGISTER_PATH2 = "register"
JSON_CATEGORY_KEY = "_category"
JSON_LENGTH_KEY = "_length"

# DICTIONARY KEYS
CATEGORY_KEY = "category"
LENGTH_KEY = "length"

# STRINGS
LENGTH_STRING_START = "VAR"

# PATHS
# -------- used for debugging ----------
ARM_JSON_PATH = "C:/Users/tmdud/Documents/GitHub/4.2/jarv1s/preprocessor/arm.json"
METAPC_JSON_PATH = "C:/Users/tmdud/Documents/GitHub/4.2/jarv1s/preprocessor/metapc.json"
# -------- relative paths ----------
# ARM_JSON_PATH = "arm.json"
# METAPC_JSON_PATH = "metapc.json"

# Recursive function to go throught all the combinations of different options that can be added at the end of the opcode
def recurse(suffixType, index):
    for suffixGroup in arm_data[JSON_ARCHITECTURE_PATH][JSON_SUFFIXGROUPS_PATH][JSON_SUFFIXGROUP_KEY]:
        if suffixGroup[JSON_IDENTIFIER_KEY] == suffixType:
            localIndex = 0
            suffixes[index] = suffixGroup[JSON_IDENTIFIER_KEY][localIndex]
            for suffix in suffixGroup[JSON_SUFFIX_KEY]:
                suffixes[index] = suffix
                if index+1 < len(suffixTypes):
                    recurse(suffixTypes[index+1], index+1)
                else:
                    string = baseIdentifier
                    for suffix in suffixes:
                        if suffix != None:
                            string += suffix
                    # print(string)
                    OpCodeReMap[ARCHITECTURE_ARM][string] = baseIdentifier

# opening json files
arm_file = open(ARM_JSON_PATH, 'r')
metapc_file = open(METAPC_JSON_PATH, 'r')
arm_data = json.load(arm_file)
metapc_data = json.load(metapc_file)

# creation of dictionaries
OpCodeReMap = {}
regReMap = {}

for architecture in architectures:
    OpCodeReMap[architecture] = {}
    regReMap[architecture] = {}

# // -- ARM -- \\

# Joining arm opcodes with jumpcodes
operations = arm_data[JSON_ARCHITECTURE_PATH][JSON_OPERATIONS_PATH][JSON_OPERATION_PATH]
for operation in arm_data[JSON_ARCHITECTURE_PATH][JSON_OPERATION_JUMPS_PATH][JSON_OPERATION_PATH]:
    operations.append(operation)

# Populate arm opcode dictionary
for operation in operations:
    baseIdentifier = operation[JSON_IDENTIFIER_KEY] # pour chaque base identifier
    if JSON_SUFFIXGROUP_KEY in operation: # s'il y a des suffix à ajouter
        suffixes = []
        suffixTypes = []
        for suffixType in operation[JSON_SUFFIXGROUP_KEY]:
            suffixTypes.append(suffixType)
            suffixes.append(None)
        recurse(suffixTypes[0], 0)

# Populate Arm Register dictionary
for register in arm_data[JSON_ARCHITECTURE_PATH][JSON_REGISTER_PATH1][JSON_REGISTER_PATH2]:
    regReMap[ARCHITECTURE_ARM][register[JSON_IDENTIFIER_KEY]] = {CATEGORY_KEY : register[JSON_CATEGORY_KEY], LENGTH_KEY : register[JSON_LENGTH_KEY]}

# // -- METAPC -- \\

# Populate Arm Register dictionary
for register in metapc_data[JSON_ARCHITECTURE_PATH][JSON_REGISTER_PATH1][JSON_REGISTER_PATH2]:
    regReMap[ARCHITECTURE_METAPC][register[JSON_IDENTIFIER_KEY]] = {CATEGORY_KEY : register[JSON_CATEGORY_KEY], LENGTH_KEY : register[JSON_LENGTH_KEY]}

# // -- FUNCTIONS -- \\

def normalizeRegister(architecture, register, normalisation):
    register = register.upper()
    if register in regReMap[architecture]:
        if normalisation == NORM_CATEGORY:
            return regReMap[architecture][register][CATEGORY_KEY]
        elif normalisation == NORM_LENGTH:
            return LENGTH_STRING_START + regReMap[architecture][register][LENGTH_KEY]
        elif normalisation == NORM_BOTH:
            return regReMap[architecture][register][CATEGORY_KEY] + regReMap[architecture][register][LENGTH_KEY]
        else:
            return NORM_UNIDF
    else:
        return NORM_UNIDF

def normalizeOpCode(architecture, opCode):
    if architecture == ARCHITECTURE_ARM:
        if opCode in OpCodeReMap[ARCHITECTURE_ARM]:
            return OpCodeReMap[ARCHITECTURE_ARM][opCode]
        else:
            return NORM_UNIDF
    elif architecture == ARCHITECTURE_METAPC:
        return opCode
    else:
        return NORM_UNIDF

def test():
    errors = []
    testFile = open("C:/Users/tmdud/Documents/GitHub/4.2/jarv1s/preprocessor/metapctest.json") # Change the test file here
    test_data = json.load(testFile)
    for block in test_data["blocks"]:
        for instruction in block["ins"]:
            normOpCode = normalizeOpCode(ARCHITECTURE_ARM, instruction["mne"])
            if normOpCode == NORM_UNIDF:
                if instruction["mne"] not in errors:
                    # errors.append("ERROR - " + instruction["mne"])
                    pass
            else:
                # print(instruction["mne"] + " -> " + normOpCode)
                pass
            if instruction["opr"]:
                splitRegisters = []
                spaceCount = instruction["opr"].count(" ")
                registers = []
                if spaceCount:
                    tempRegisters = instruction["opr"].split(" ")
                    for register in tempRegisters:
                        if not (register[0] == '#' or register[0] == '[' or register[0] == '='):
                            registers.append(register)
                else:
                    registers = [instruction["opr"]]
                
                for register in registers:
                    if register[0] == '{' or register[0] == '[':
                        register = register.replace("{", "").replace("}","")
                        commaCount = register.count(",")
                        if commaCount:
                            subRegisters = register.split(",")
                            for subRegister in subRegisters:
                                subCount = subRegister.count("-")
                                addCount = subRegister.count("+")
                                if subCount:
                                    opRegisters = subRegister.split("-")
                                    for opRegister in opRegisters:
                                        registers.append(opRegister)
                                elif addCount:
                                    opRegisters = subRegister.split("+")
                                    for opRegister in opRegisters:
                                        registers.append(opRegister)
                                else:
                                    splitRegisters.append(subRegister)
                    else:
                        splitRegisters.append(register)

                for register in splitRegisters:
                    if not(register == "state" or register =="strm" or register.startswith("loc_") or register.startswith("_") or register.startswith("fs:") or register.startswith("dword") or register.startswith("word") or register.startswith("ds:") or register.startswith("unk_") or register.startswith("sub") or register.startswith("off") or register.startswith("def") or register.startswith("locret") or register.startswith("stru") or register.startswith(tuple('0123456789'))):
                        normReg = normalizeRegister(ARCHITECTURE_ARM, register, NORM_BOTH) # Change the norm type here
                        if normReg == NORM_UNIDF:
                            if "ERROR - " + register not in errors:
                                errors.append("ERROR - " + register)
                        # else:
                            # print(register + " -> " + normReg)
    print("// -- ERRORS -- \\\\")
    for error in errors:
        print(error)

# // -- TESTS -- \\

# test()
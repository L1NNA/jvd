package ca.l1nna.ghidra;

import generic.stl.Pair;
import ghidra.GhidraJarApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.Platform;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.*;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.io.FileUtils;

import ca.l1nna.ghidra.Model.Binary;
import ca.l1nna.ghidra.Model.Block;
import ca.l1nna.ghidra.Model.Ins;
import ca.l1nna.ghidra.Model.Comment;
import ca.l1nna.ghidra.Model.Func;
import ca.l1nna.ghidra.Model.FuncSrc;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;

public class GhidraDecompiler {
    private File binaryFile = null;
    private Program currentProgram = null;
    private GhidraProject ghidra_project = null;
    private CodeBlockModel code_block_model = null;
    private FlatProgramAPI fApi = null;
    private TestProgramManager program_manager = null;
    private static final SimpleDateFormat date_formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    GhidraDecompiler(String path_to_binary, String ghidra_project_dir)
            throws IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {
        this.binaryFile = new File(path_to_binary);
        program_manager = new TestProgramManager();

        // Initialize application
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setScriptLogFile(null);
            configuration.setApplicationLogFile(null);
            configuration.setInitializeLogging(false);
            // noisy
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Create a Ghidra project
        ghidra_project = GhidraProject.createProject(ghidra_project_dir, "TempProject", true);

        currentProgram = ghidra_project.importProgram(this.binaryFile);
        /*
         * SimpleBlockModel URL
         * https://ghidra.re/ghidra_docs/api/ghidra/program/model/block/SimpleBlockModel
         * .html
         *
         * Any instruction with a label starts a block. Each instruction that could
         * cause program control flow to change is the last instruction of a Codeblock.
         * All other instructions are "NOP" fallthroughs, meaning after execution the
         * program counter will be at the instruction immediately following. Any
         * instruction that is unreachable and has no label is also considered the start
         * of a block.
         */
        code_block_model = new SimpleBlockModel(currentProgram);
        fApi = new FlatProgramAPI(currentProgram);
    }

    private String getBinaryId() {
        return currentProgram.getExecutableSHA256();
    }

    private String getFuncId(long sea) {
        return Hashing.sha256().hashString(this.getBinaryId() + "f" + sea, StandardCharsets.UTF_8).toString();
    }

    private String getBlkId(long sea) {
        return Hashing.sha256().hashString(this.getBinaryId() + "b" + sea, StandardCharsets.UTF_8).toString();
    }

    public void close() {
        // Cleanup the project
        program_manager.release(currentProgram);
        ghidra_project.close();
    }

    public void dump(String file) {
        try {
            Model model = new Model();
            model.bin = ParseBinary();
            model.functions = ParseFunctions();
            model.blocks = ParseBlocks();
            model.comments = ParseComments();

            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(new File(file), model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public List<Block> ParseBlocks() throws Exception {
        /**
         * Parses the program to find all blocks
         * 
         * @return JSON representing "addr_start": 268439552, "bin_id", "name", "calls",
         *         "addr_end", "ins"[{ "ea", "mne", "opr"}], "func_id",001009a0 "ins_c",
         *         "_id"
         */
        List<Block> blocks = new ArrayList<>();
        CodeBlockIterator codeBlockItr = code_block_model.getCodeBlocks(TaskMonitor.DUMMY);
        while (codeBlockItr.hasNext()) {
            CodeBlock code_block = codeBlockItr.next();
            Block block = new Block();
            block.addr_start = code_block.getFirstStartAddress().getOffset();
            block.bin_id = getBinaryId();
            block.name = code_block.getName();

            CodeBlockReferenceIterator codeBlockReferenceDestsIterator = code_block.getDestinations(TaskMonitor.DUMMY);
            while (codeBlockReferenceDestsIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                block.calls.add(this.getBlkId(codeBlockDest.getFirstStartAddress().getOffset()));
            }
            block.addr_end = code_block.getMaxAddress().getOffset();

            // There should only ever be 1 range since we are using SimpleBlockModel
            int range_count = 0;
            for (AddressRange range : code_block.getAddressRanges()) {
                if (range_count > 0) {
                    System.err.println("MULTIPLE RANGES PARSED FROM BLOCK!");
                }
                block.ins.addAll(ParseInstructionsFromRange(range));
                range_count++;
            }
            blocks.add(block);
        }

        return blocks;
    }

    private List<String> getInternalFuncRef(AddressSetView view) {
        List<String> refs = new ArrayList<>();
        FunctionIterator function_itr = currentProgram.getFunctionManager().getFunctions(view, true);
        while (function_itr.hasNext()) {
            Function function = function_itr.next();
            if (function != null && !function.isExternal())
                refs.add(getFuncId(function.getEntryPoint().getOffset()));
        }
        return refs;
    }

    private List<Ins> ParseInstructionsFromRange(AddressRange range) {
        /**
         * Parses a range of addresses extracting all instructions
         */

        List<Ins> all = new ArrayList<>();
        for (Address cur = range.getMinAddress(); range.getMaxAddress().subtract(cur) >= 0;) {
            Instruction instruction = fApi.getInstructionAt(cur);
            if (instruction == null)
                break;
            Ins ins = new Ins();
            ins.ea = instruction.getAddress().getOffset();
            ins.mne = instruction.getMnemonicString();
            ins.oprs.add(instruction.toString());
            all.add(ins);
            cur = instruction.getMaxAddress().next();
        }

        return all;
    }

    public List<Comment> ParseComments() throws CancelledException {
        /**
         * "category": "content": "block_id" "author": "Ghidra", "binary_id"
         * "created_at" "function_id" "address"
         */
        List<Comment> comments = new ArrayList<>();
        ArrayList<Pair<String, Integer>> comment_category_map = new ArrayList<>();
        comment_category_map.add(new Pair<>("anterior", CodeUnit.PRE_COMMENT));
        comment_category_map.add(new Pair<>("posterior", CodeUnit.POST_COMMENT));
        comment_category_map.add(new Pair<>("regular", CodeUnit.PLATE_COMMENT));
        comment_category_map.add(new Pair<>("repeatable", CodeUnit.REPEATABLE_COMMENT));

        Listing listing = currentProgram.getListing();
        for (Pair<String, Integer> p : comment_category_map) {
            int comment_category = p.second;
            String comment_type = p.first;

            AddressIterator forward_comment_itr = listing.getCommentAddressIterator(comment_category,
                    currentProgram.getMemory(), true);

            while (forward_comment_itr.hasNext()) {
                Address address = forward_comment_itr.next();
                String content = listing.getComment(comment_category, address);

                // Can return null comments for some reason? Weird.
                if (content == null)
                    continue;

                Comment comment = new Comment();
                comment.category = comment_type;
                comment.content = content;
                // This assumes simple block model so no overlap is possible
                CodeBlock block_containing_comment = code_block_model.getFirstCodeBlockContaining(address,
                        TaskMonitor.DUMMY);
                comment.block_id = block_containing_comment == null ? "null" : block_containing_comment.getName();
                comment.author = "Ghidra";
                comment.binary_id = getBinaryId();
                comment.created_at = date_formatter.format(Calendar.getInstance().getTime());

                Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
                comment.function_id = getFuncId(function.getEntryPoint().getOffset());
                comment.address = address.getOffset();
                comments.add(comment);
            }

        }
        return comments;
    }

    public List<Func> ParseFunctions() {
        List<Func> functions = new ArrayList<>();
        for (Function current_function = fApi.getFirstFunction(); current_function != null; current_function = fApi
                .getFunctionAfter(current_function)) {
            Func func = new Func();
            func.addr_start = current_function.getEntryPoint().getOffset();
            func._id = getFuncId(func.addr_start);
            func.name = current_function.getName();
            func.calls = getInternalFuncRef(current_function.getBody());
            func.api = getExternalFuncRef(current_function);
            func.bin_id = getBinaryId();
            func.addr_end = current_function.getBody().getMaxAddress().getOffset();
            functions.add(func);
        }
        return functions;
    }

    private List<String> getExternalFuncRef(Function function) {
        List<String> apis = new ArrayList<>();
        for (Function called_function : function.getCalledFunctions(TaskMonitor.DUMMY)) {
            apis.add(called_function.getName());
        }
        return apis;
    }

    private List<String> getAllStrings(Program program) {
        /**
         * Parses the program to find all strings
         * 
         * @return List of strings in the program
         */

        HashSet<String> output = new HashSet<>();
        Listing listing = program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data nextData = dataIterator.next();
            String type = nextData.getDataType().getName().toLowerCase();
            if (type.contains("unicode") || type.contains("string")) {
                if (nextData != null && nextData.getValue() != null) {
                    output.add(nextData.getValue().toString());
                }
            }
        }
        return Lists.newArrayList(output);
    }

    public Binary ParseBinary() {
        /**
         * Parses the current program
         * 
         * @return JSON representing "import_modules", "name", "import_functions",
         *         "description", "disassembled_at", "functions_count", "architecture",
         *         "endian", "disassembler", "_id", "bits", "strings", "compiler"
         */

        Binary bin = new Binary();
        FunctionIterator external_function_itr = currentProgram.getListing().getExternalFunctions();
        while (external_function_itr.hasNext()) {
            Function function = external_function_itr.next();
            if (function != null) {
                bin.import_functions.add(function.getName());
                if (function.getProgram() != null)
                    bin.import_modules.add(function.getProgram().getName());
            }
        }
        bin.name = this.binaryFile.getName();
        bin.disassembled_at = date_formatter.format(Calendar.getInstance().getTime());
        bin.functions_count = currentProgram.getFunctionManager().getFunctionCount();
        bin.architecture = Platform.CURRENT_PLATFORM.getArchitecture().toString();
        bin.endian = currentProgram.getLanguage().isBigEndian() ? "be" : "le";
        bin._id = getBinaryId();
        bin.bits = "b" + currentProgram.getAddressFactory().getDefaultAddressSpace().getSize();
        bin.strings = getAllStrings(currentProgram);
        bin.compiler = currentProgram.getCompiler();
        return bin;
    }

}
package ca.l1nna.ghidra;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.StreamSupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.hash.Hashing;

import ca.l1nna.ghidra.Model.Binary;
import ca.l1nna.ghidra.Model.Block;
import ca.l1nna.ghidra.Model.Comment;
import ca.l1nna.ghidra.Model.Func;
import ca.l1nna.ghidra.Model.FuncSrc;
import ca.l1nna.ghidra.Model.Ins;
import generic.stl.Pair;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.decompiler.DecompInterface;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.Platform;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.OperandRepresentationList;
import ghidra.program.model.listing.Program;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class GhidraDecompiler {
    private File binaryFile = null;
    private Program program = null;
    private GhidraProject project = null;
    private TestProgramManager manager = null;
    private static final SimpleDateFormat date_formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    private BasicBlockModel basicBlockModel = null;
    private FunctionManager functionManager = null;
    private TaskMonitor monitor = TaskMonitor.DUMMY;
    private CodeUnitFormat format = new CodeUnitFormat(new CodeUnitFormatOptions());
    private DecompInterface decomp = null;
    private boolean decompiled;

    GhidraDecompiler(String binPath, String projPath, boolean decompiled)
            throws IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {

        this.binaryFile = new File(binPath);
        this.decompiled = decompiled;
        manager = new TestProgramManager();

        // Initialize application
        if (!Application.isInitialized()) {
            ApplicationConfiguration conf = new HeadlessGhidraApplicationConfiguration();
            conf.setScriptLogFile(null);
            conf.setApplicationLogFile(null);
            conf.setInitializeLogging(false);
            // noisy
            Application.initializeApplication(new GhidraJarApplicationLayout(), conf);
        }

        // Create a Ghidra project
        project = GhidraProject.createProject(projPath, "TempProject", true);
        program = project.importProgram(this.binaryFile);
        basicBlockModel = new BasicBlockModel(program);
        functionManager = program.getFunctionManager();
        GhidraProject.analyze(program);
        if (decompiled) {
            decomp = new DecompInterface();
            decomp.openProgram(program);
        }
    }

    private String getBinaryId() {
        return program.getExecutableSHA256();
    }

    private String getFuncId(long sea) {
        return Hashing.sha256().hashString(this.getBinaryId() + "f" + sea, StandardCharsets.UTF_8).toString();
    }

    private String getBlkId(long sea) {
        return Hashing.sha256().hashString(this.getBinaryId() + "b" + sea, StandardCharsets.UTF_8).toString();
    }

    public void close() {
        manager.release(program);
        project.close();
    }

    public void dump(String file) {
        try {

            Model model = new Model();

            Binary bin = new Binary();
            StreamSupport.stream(program.getListing().getExternalFunctions().spliterator(), false)
                    .forEach(func->bin.import_functions.put(func.getEntryPoint().getOffset(), func.getName()));
            bin.name = this.binaryFile.getName();
            bin.disassembled_at = date_formatter.format(Calendar.getInstance().getTime());
            bin.functions_count = functionManager.getFunctionCount();
            bin.architecture = Platform.CURRENT_PLATFORM.getArchitecture().toString();
            bin.endian = program.getLanguage().isBigEndian() ? "be" : "le";
            bin._id = getBinaryId();
            bin.bits = "b" + program.getAddressFactory().getDefaultAddressSpace().getSize();
            StreamSupport
                    .stream(program.getListing().getDefinedData(true).spliterator(), false).map(dat -> dat.getValue())
                    .filter(dat -> dat != null).forEach(dat -> bin.strings.put(dat.getAddress().getOffeset(), dat.toString().replaceAll("\\s", "_")));
            // if (type.contains("unicode") || type.contains("string")) {
            bin.compiler = program.getCompiler();
            model.bin = bin;

            for (Function currentFunction : functionManager.getFunctions(true)) {

                Func func = new Func();
                func.addr_start = currentFunction.getEntryPoint().getOffset();
                func._id = getFuncId(func.addr_start);
                func.name = currentFunction.getName();
                func.calls = currentFunction.getCallingFunctions(monitor).stream().filter(f -> !f.isExternal())
                        .map(f -> this.getFuncId(f.getEntryPoint().getOffset())).collect(Collectors.toList());
                func.api = currentFunction.getCallingFunctions(monitor).stream().filter(f -> f.isExternal())
                        .map(f -> f.getName()).collect(Collectors.toList());
                func.bin_id = bin._id;
                func.addr_end = currentFunction.getBody().getMaxAddress().getOffset();
                model.functions.add(func);

                if (this.decompiled) {
                    FuncSrc funcSrc = new FuncSrc();
                    funcSrc._id = func._id;
                    funcSrc.src = decomp.decompileFunction(currentFunction, 0, monitor).getDecompiledFunction().getC();
                    model.functions_src.add(funcSrc);
                }

                CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(currentFunction.getBody(),
                        monitor);
                while (codeBlockIterator.hasNext()) {
                    CodeBlock codeBlock = codeBlockIterator.next();

                    Block block = new Block();
                    block.addr_start = codeBlock.getFirstStartAddress().getOffset();
                    block._id = this.getBlkId(block.addr_start);
                    block.bin_id = model.bin._id;
                    block.func_id = func._id;
                    block.name = codeBlock.getName();
                    model.blocks.add(block);

                    CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(monitor);
                    while (codeBlockReferenceDestsIterator.hasNext()) {
                        CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                        CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                        block.calls.add(this.getBlkId(codeBlockDest.getFirstStartAddress().getOffset()));
                    }

                    Listing listing = program.getListing();
                    CodeUnitIterator codeUnitIterator = listing.getCodeUnits(codeBlock, true);
                    while (codeUnitIterator.hasNext()) {
                        CodeUnit cu = codeUnitIterator.next();
                        if (cu instanceof Instruction) {
                            Instruction instr = (Instruction) cu;
                            Ins ins = new Ins();
                            ins.ea = instr.getAddress().getOffset();
                            ins.mne = instr.getMnemonicString();
                            for (int i = 0; i < instr.getNumOperands(); ++i) {
                                ins.oprs.add(format.getOperandRepresentationString(cu, i));
                                ins.oprs_tp.add(Integer
                                        .toString(instr.getPrototype().getOpType(i, instr.getInstructionContext())));
                            }
                            block.ins.add(ins);
                        }
                    }
                }
            }

            model.comments = ParseComments();

            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(new File(file), model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public List<Comment> ParseComments() throws CancelledException {
        List<Comment> comments = new ArrayList<>();
        ArrayList<Pair<String, Integer>> comment_category_map = new ArrayList<>();
        comment_category_map.add(new Pair<>("anterior", CodeUnit.PRE_COMMENT));
        comment_category_map.add(new Pair<>("posterior", CodeUnit.POST_COMMENT));
        comment_category_map.add(new Pair<>("regular", CodeUnit.PLATE_COMMENT));
        comment_category_map.add(new Pair<>("repeatable", CodeUnit.REPEATABLE_COMMENT));

        Listing listing = program.getListing();
        for (Pair<String, Integer> p : comment_category_map) {
            int comment_category = p.second;
            String comment_type = p.first;

            AddressIterator forward_comment_itr = listing.getCommentAddressIterator(comment_category,
                    program.getMemory(), true);

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
                CodeBlock block_containing_comment = basicBlockModel.getFirstCodeBlockContaining(address,
                        TaskMonitor.DUMMY);
                comment.blk_id = block_containing_comment == null ? "null" : block_containing_comment.getName();
                comment.author = "Ghidra";
                comment.bin_id = getBinaryId();
                comment.created_at = date_formatter.format(Calendar.getInstance().getTime());

                Function function = program.getFunctionManager().getFunctionContaining(address);
                if (function != null) {
                    comment.func_id = getFuncId(function.getEntryPoint().getOffset());
                    comment.address = address.getOffset();
                    comments.add(comment);
                }
            }
        }

        return comments;

    }

}
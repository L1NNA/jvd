package ca.l1nna.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class Model {

    public Binary bin;
    public List<Func> functions = new ArrayList<>();
    public List<FuncSrc> functions_src = new ArrayList<>();
    public List<Block> blocks = new ArrayList<>();
    public List<Comment> comments = new ArrayList<>();

    public static class Binary {
        public List<String> import_modules = new ArrayList<>();
        public Map<Long, String> import_functions = new HashMap<>();
        public String description = "";
        public String disassembled_at = "";
        public int functions_count = 0;
        public String architecture = "";
        public String disassembler = "ghidra";
        public String endian = "";
        public String _id = "";
        public String bits = "";
        public Map<Long, String> strings = new HashMap<>();
        public String compiler = "";
        public String name;

    }

    public static class Func {
        public long addr_start;
        public String _id = "";
        public List<String> calls;
        public String bin_id = "";
        public int bbs_len = 0;
        public long addr_end;
        public String description = "";
        public String name = "";
        public List<String> api = new ArrayList<>();
    }

    public static class FuncSrc {
        public String _id = "";
        public String src = "";
    }

    public static class Block {
        public long addr_start;
        public String bin_id = "";
        public String func_id = "";
        public String _id = "";
        public String name = "";
        public List<String> calls = new ArrayList<>();
        public long addr_end;
        public List<Ins> ins = new ArrayList<>();
    }

    public static class Ins {
        public long ea;
        public String mne = "";
        public List<String> oprs = new ArrayList<>();
        public List<String> oprs_tp = new ArrayList<>();
    }

    public static class Comment {
        public String category = "";
        public String content = "";
        public String blk_id = "";
        public String author = "ghidra";
        public String bin_id = "";
        public String created_at = "";
        public String func_id = "";
        public long address;
    }
}
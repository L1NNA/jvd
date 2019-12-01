package ca.l1nna.ghidra;

import java.io.IOException;

import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;

public class GhidraMain {

    public static void main(String[] args) {
        if (args.length > 0) {
            String bin = args[0];
            String json = args[1];
            String ghidra_project = args[2];

            GhidraDecompiler decompiler;
            try {
                decompiler = new GhidraDecompiler(bin, ghidra_project);
                decompiler.dump(json);
                decompiler.close();
            } catch (VersionException | CancelledException | DuplicateNameException | InvalidNameException
                    | IOException e) {
                e.printStackTrace();
            }
        }

    }
}
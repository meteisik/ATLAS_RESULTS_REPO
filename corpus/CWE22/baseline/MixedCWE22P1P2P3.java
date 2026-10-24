package cwe22.mixed;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class MixedCWE22P1P2P3 {

    // Violation 1 (P01, Juliet _01): an environment value is appended to the
    // upload root and opened in the same method.
    public void openInlineUpload() throws IOException {
        String data;
        data = System.getenv("INLINE_PATH");
        String inlineRoot = "/home/user/uploads/";
        File inlineFile = new File(inlineRoot + data);
        FileInputStream inlineStream = new FileInputStream(inlineFile);
        inlineStream.close();
    }

    // Violation 2 (P02, Juliet _31): the environment value is copied to a
    // second local inside a nested block; a later block re-reads the copy,
    // appends it to the upload root and opens the file.
    public void openCopiedUpload() throws IOException {
        String dataCopy;
        {
            String data;
            data = System.getenv("COPIED_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String copiedRoot = "/home/user/uploads/";
            File copiedFile = new File(copiedRoot + data);
            FileInputStream copiedStream = new FileInputStream(copiedFile);
            copiedStream.close();
        }
    }

    // Violation 3 (P03, Juliet _41): the environment value is passed to a
    // private helper that appends it to the upload root and opens the file.
    public void openHelperUpload() throws IOException {
        String data;
        data = System.getenv("HELPER_PATH");
        readHelperUpload(data);
    }

    private void readHelperUpload(String data) throws IOException {
        String helperRoot = "/home/user/uploads/";
        File helperFile = new File(helperRoot + data);
        FileInputStream helperStream = new FileInputStream(helperFile);
        helperStream.close();
    }

}

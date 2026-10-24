import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P10_V1_RuneHelix {
    public static String data;

    public void openRuneHelix() throws IOException {
        data = System.getenv("RUNE_HELIX_PATH");
        (new CWE22_P10_V1_RuneHelixSink()).readRuneHelix();
    }
}

class CWE22_P10_V1_RuneHelixSink {
    public void readRuneHelix() throws IOException {
        String data = CWE22_P10_V1_RuneHelix.data;
        String runeHelixRoot = "/home/user/uploads/";
        File runeHelixFile = new File(runeHelixRoot + data);
        FileInputStream runeHelixStream = new FileInputStream(runeHelixFile);
        runeHelixStream.close();
    }
}

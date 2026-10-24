import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_RuneHelix {

    public void openRuneHelix() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_HELIX_PATH");
        }
        (new CWE22_P06_V2_RuneHelixSink()).readRuneHelix(data);
    }
}

class CWE22_P06_V2_RuneHelixSink {
    public void readRuneHelix(String data) {
        String runeHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File runeHelixFile = new File(runeHelixRoot + data);
            FileInputStream runeHelixStream = null;
            InputStreamReader runeHelixStreamReader = null;
            BufferedReader runeHelixReader = null;
            if (runeHelixFile.exists() && runeHelixFile.isFile()) {
                try {
                    runeHelixStream = new FileInputStream(runeHelixFile);
                    runeHelixStreamReader = new InputStreamReader(runeHelixStream, "UTF-8");
                    runeHelixReader = new BufferedReader(runeHelixStreamReader);
                    System.out.println(runeHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_RuneHelixSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeHelixReader != null) {
                            runeHelixReader.close();
                        }
                        if (runeHelixStreamReader != null) {
                            runeHelixStreamReader.close();
                        }
                        if (runeHelixStream != null) {
                            runeHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_RuneHelixSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

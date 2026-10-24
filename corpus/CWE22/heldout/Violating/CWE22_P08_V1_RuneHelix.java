import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_RuneHelix {

    public void openRuneHelix() {
        String data;
        data = System.getenv("RUNE_HELIX_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_RuneHelixSink()).readRuneHelix(dataArray);
    }
}

class CWE22_P08_V1_RuneHelixSink {
    public void readRuneHelix(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V1_RuneHelixSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V1_RuneHelixSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

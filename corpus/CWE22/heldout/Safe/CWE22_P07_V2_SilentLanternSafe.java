import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SilentLanternSafe {
    private static int privateFive = 5;

    public void openSilentLantern() {
        String data;
        if (privateFive == 5) {
            data = (new CWE22_P07_V2_SilentLanternSafeSource()).locateSilentLantern();
        } else {
            data = null;
        }
        String silentLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File silentLanternFile = new File(silentLanternRoot + data);
            FileInputStream silentLanternStream = null;
            InputStreamReader silentLanternStreamReader = null;
            BufferedReader silentLanternReader = null;
            if (silentLanternFile.exists() && silentLanternFile.isFile()) {
                try {
                    silentLanternStream = new FileInputStream(silentLanternFile);
                    silentLanternStreamReader = new InputStreamReader(silentLanternStream, "UTF-8");
                    silentLanternReader = new BufferedReader(silentLanternStreamReader);
                    System.out.println(silentLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SilentLanternSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentLanternReader != null) {
                            silentLanternReader.close();
                        }
                        if (silentLanternStreamReader != null) {
                            silentLanternStreamReader.close();
                        }
                        if (silentLanternStream != null) {
                            silentLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SilentLanternSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SilentLanternSafeSource {
    public String locateSilentLantern() {
        String data;
        data = "foo";
        return data;
    }
}

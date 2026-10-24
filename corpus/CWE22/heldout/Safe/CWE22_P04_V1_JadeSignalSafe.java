import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_JadeSignalSafe {

    private String locateJadeSignal() {
        String data;
        data = "foo";
        return data;
    }

    public void openJadeSignal() {
        String data = locateJadeSignal();
        String jadeSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeSignalFile = new File(jadeSignalRoot + data);
            FileInputStream jadeSignalStream = null;
            InputStreamReader jadeSignalStreamReader = null;
            BufferedReader jadeSignalReader = null;
            if (jadeSignalFile.exists() && jadeSignalFile.isFile()) {
                try {
                    jadeSignalStream = new FileInputStream(jadeSignalFile);
                    jadeSignalStreamReader = new InputStreamReader(jadeSignalStream, "UTF-8");
                    jadeSignalReader = new BufferedReader(jadeSignalStreamReader);
                    System.out.println(jadeSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_JadeSignalSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeSignalReader != null) {
                            jadeSignalReader.close();
                        }
                        if (jadeSignalStreamReader != null) {
                            jadeSignalStreamReader.close();
                        }
                        if (jadeSignalStream != null) {
                            jadeSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_JadeSignalSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

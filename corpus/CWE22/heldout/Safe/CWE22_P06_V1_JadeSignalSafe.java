import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadeSignalSafe {

    public void openJadeSignal() {
        String data;
        data = "foo";
        (new CWE22_P06_V1_JadeSignalSafeSink()).readJadeSignal(data);
    }
}

class CWE22_P06_V1_JadeSignalSafeSink {
    public void readJadeSignal(String data) {
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
                    Logger.getLogger("CWE22_P06_V1_JadeSignalSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P06_V1_JadeSignalSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

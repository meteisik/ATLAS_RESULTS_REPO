import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_VividSignalSafe {
    public static String data;

    public void openVividSignal() {
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_VividSignalSafeSink()).readVividSignal();
    }
}

class CWE22_P10_V2_VividSignalSafeSink {
    public void readVividSignal() {
        String data = CWE22_P10_V2_VividSignalSafe.data;
        String vividSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File vividSignalFile = new File(vividSignalRoot + data);
            FileInputStream vividSignalStream = null;
            InputStreamReader vividSignalStreamReader = null;
            BufferedReader vividSignalReader = null;
            if (vividSignalFile.exists() && vividSignalFile.isFile()) {
                try {
                    vividSignalStream = new FileInputStream(vividSignalFile);
                    vividSignalStreamReader = new InputStreamReader(vividSignalStream, "UTF-8");
                    vividSignalReader = new BufferedReader(vividSignalStreamReader);
                    System.out.println(vividSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_VividSignalSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividSignalReader != null) {
                            vividSignalReader.close();
                        }
                        if (vividSignalStreamReader != null) {
                            vividSignalStreamReader.close();
                        }
                        if (vividSignalStream != null) {
                            vividSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_VividSignalSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

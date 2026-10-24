import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_SaffronSignal {
    public static String data;

    public void openSaffronSignal() {
        data = System.getenv("SAFFRON_SIGNAL_PATH");
        (new CWE22_P10_V1_SaffronSignalSink()).readSaffronSignal();
    }
}

class CWE22_P10_V1_SaffronSignalSink {
    public void readSaffronSignal() {
        String data = CWE22_P10_V1_SaffronSignal.data;
        String saffronSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronSignalFile = new File(saffronSignalRoot + data);
            FileInputStream saffronSignalStream = null;
            InputStreamReader saffronSignalStreamReader = null;
            BufferedReader saffronSignalReader = null;
            if (saffronSignalFile.exists() && saffronSignalFile.isFile()) {
                try {
                    saffronSignalStream = new FileInputStream(saffronSignalFile);
                    saffronSignalStreamReader = new InputStreamReader(saffronSignalStream, "UTF-8");
                    saffronSignalReader = new BufferedReader(saffronSignalStreamReader);
                    System.out.println(saffronSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V1_SaffronSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronSignalReader != null) {
                            saffronSignalReader.close();
                        }
                        if (saffronSignalStreamReader != null) {
                            saffronSignalStreamReader.close();
                        }
                        if (saffronSignalStream != null) {
                            saffronSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V1_SaffronSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

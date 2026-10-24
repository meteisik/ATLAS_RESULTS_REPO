import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrSignal {

    public void openZephyrSignal() {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_PATH");
        CWE22_P12_V1_ZephyrSignalBase baseObject = new CWE22_P12_V1_ZephyrSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrSignalBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrSignalSink extends CWE22_P12_V1_ZephyrSignalBase {
    public void action(String data) {
        String zephyrSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrSignalFile = new File(zephyrSignalRoot + data);
            FileInputStream zephyrSignalStream = null;
            InputStreamReader zephyrSignalStreamReader = null;
            BufferedReader zephyrSignalReader = null;
            if (zephyrSignalFile.exists() && zephyrSignalFile.isFile()) {
                try {
                    zephyrSignalStream = new FileInputStream(zephyrSignalFile);
                    zephyrSignalStreamReader = new InputStreamReader(zephyrSignalStream, "UTF-8");
                    zephyrSignalReader = new BufferedReader(zephyrSignalStreamReader);
                    System.out.println(zephyrSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrSignalReader != null) {
                            zephyrSignalReader.close();
                        }
                        if (zephyrSignalStreamReader != null) {
                            zephyrSignalStreamReader.close();
                        }
                        if (zephyrSignalStream != null) {
                            zephyrSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrPrismSafe {

    public void openZephyrPrism() {
        String data;
        data = "foo";
        CWE22_P12_V1_ZephyrPrismSafeBase baseObject = new CWE22_P12_V1_ZephyrPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrPrismSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrPrismSafeSink extends CWE22_P12_V1_ZephyrPrismSafeBase {
    public void action(String data) {
        String zephyrPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrPrismFile = new File(zephyrPrismRoot + data);
            FileInputStream zephyrPrismStream = null;
            InputStreamReader zephyrPrismStreamReader = null;
            BufferedReader zephyrPrismReader = null;
            if (zephyrPrismFile.exists() && zephyrPrismFile.isFile()) {
                try {
                    zephyrPrismStream = new FileInputStream(zephyrPrismFile);
                    zephyrPrismStreamReader = new InputStreamReader(zephyrPrismStream, "UTF-8");
                    zephyrPrismReader = new BufferedReader(zephyrPrismStreamReader);
                    System.out.println(zephyrPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrPrismReader != null) {
                            zephyrPrismReader.close();
                        }
                        if (zephyrPrismStreamReader != null) {
                            zephyrPrismStreamReader.close();
                        }
                        if (zephyrPrismStream != null) {
                            zephyrPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

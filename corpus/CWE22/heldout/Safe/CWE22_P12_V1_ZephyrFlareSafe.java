import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrFlareSafe {

    public void openZephyrFlare() {
        String data;
        data = "foo";
        CWE22_P12_V1_ZephyrFlareSafeBase baseObject = new CWE22_P12_V1_ZephyrFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrFlareSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrFlareSafeSink extends CWE22_P12_V1_ZephyrFlareSafeBase {
    public void action(String data) {
        String zephyrFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrFlareFile = new File(zephyrFlareRoot + data);
            FileInputStream zephyrFlareStream = null;
            InputStreamReader zephyrFlareStreamReader = null;
            BufferedReader zephyrFlareReader = null;
            if (zephyrFlareFile.exists() && zephyrFlareFile.isFile()) {
                try {
                    zephyrFlareStream = new FileInputStream(zephyrFlareFile);
                    zephyrFlareStreamReader = new InputStreamReader(zephyrFlareStream, "UTF-8");
                    zephyrFlareReader = new BufferedReader(zephyrFlareStreamReader);
                    System.out.println(zephyrFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrFlareReader != null) {
                            zephyrFlareReader.close();
                        }
                        if (zephyrFlareStreamReader != null) {
                            zephyrFlareStreamReader.close();
                        }
                        if (zephyrFlareStream != null) {
                            zephyrFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrQuartz {

    public void openZephyrQuartz() {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_PATH");
        CWE22_P12_V1_ZephyrQuartzBase baseObject = new CWE22_P12_V1_ZephyrQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrQuartzBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrQuartzSink extends CWE22_P12_V1_ZephyrQuartzBase {
    public void action(String data) {
        String zephyrQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrQuartzFile = new File(zephyrQuartzRoot + data);
            FileInputStream zephyrQuartzStream = null;
            InputStreamReader zephyrQuartzStreamReader = null;
            BufferedReader zephyrQuartzReader = null;
            if (zephyrQuartzFile.exists() && zephyrQuartzFile.isFile()) {
                try {
                    zephyrQuartzStream = new FileInputStream(zephyrQuartzFile);
                    zephyrQuartzStreamReader = new InputStreamReader(zephyrQuartzStream, "UTF-8");
                    zephyrQuartzReader = new BufferedReader(zephyrQuartzStreamReader);
                    System.out.println(zephyrQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrQuartzReader != null) {
                            zephyrQuartzReader.close();
                        }
                        if (zephyrQuartzStreamReader != null) {
                            zephyrQuartzStreamReader.close();
                        }
                        if (zephyrQuartzStream != null) {
                            zephyrQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

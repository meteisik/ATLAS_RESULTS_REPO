import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrCascade {

    public void openZephyrCascade() {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_PATH");
        CWE22_P12_V1_ZephyrCascadeBase baseObject = new CWE22_P12_V1_ZephyrCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrCascadeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrCascadeSink extends CWE22_P12_V1_ZephyrCascadeBase {
    public void action(String data) {
        String zephyrCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrCascadeFile = new File(zephyrCascadeRoot + data);
            FileInputStream zephyrCascadeStream = null;
            InputStreamReader zephyrCascadeStreamReader = null;
            BufferedReader zephyrCascadeReader = null;
            if (zephyrCascadeFile.exists() && zephyrCascadeFile.isFile()) {
                try {
                    zephyrCascadeStream = new FileInputStream(zephyrCascadeFile);
                    zephyrCascadeStreamReader = new InputStreamReader(zephyrCascadeStream, "UTF-8");
                    zephyrCascadeReader = new BufferedReader(zephyrCascadeStreamReader);
                    System.out.println(zephyrCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrCascadeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrCascadeReader != null) {
                            zephyrCascadeReader.close();
                        }
                        if (zephyrCascadeStreamReader != null) {
                            zephyrCascadeStreamReader.close();
                        }
                        if (zephyrCascadeStream != null) {
                            zephyrCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrCascadeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

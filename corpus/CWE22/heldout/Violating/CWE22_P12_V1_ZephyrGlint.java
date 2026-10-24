import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrGlint {

    public void openZephyrGlint() {
        String data;
        data = System.getenv("ZEPHYR_GLINT_PATH");
        CWE22_P12_V1_ZephyrGlintBase baseObject = new CWE22_P12_V1_ZephyrGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrGlintBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrGlintSink extends CWE22_P12_V1_ZephyrGlintBase {
    public void action(String data) {
        String zephyrGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File zephyrGlintFile = new File(zephyrGlintRoot + data);
            FileInputStream zephyrGlintStream = null;
            InputStreamReader zephyrGlintStreamReader = null;
            BufferedReader zephyrGlintReader = null;
            if (zephyrGlintFile.exists() && zephyrGlintFile.isFile()) {
                try {
                    zephyrGlintStream = new FileInputStream(zephyrGlintFile);
                    zephyrGlintStreamReader = new InputStreamReader(zephyrGlintStream, "UTF-8");
                    zephyrGlintReader = new BufferedReader(zephyrGlintStreamReader);
                    System.out.println(zephyrGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_ZephyrGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (zephyrGlintReader != null) {
                            zephyrGlintReader.close();
                        }
                        if (zephyrGlintStreamReader != null) {
                            zephyrGlintStreamReader.close();
                        }
                        if (zephyrGlintStream != null) {
                            zephyrGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_ZephyrGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

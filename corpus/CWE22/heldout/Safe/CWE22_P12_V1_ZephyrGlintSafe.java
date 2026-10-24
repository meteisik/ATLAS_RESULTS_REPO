import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_ZephyrGlintSafe {

    public void openZephyrGlint() {
        String data;
        data = "foo";
        CWE22_P12_V1_ZephyrGlintSafeBase baseObject = new CWE22_P12_V1_ZephyrGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_ZephyrGlintSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_ZephyrGlintSafeSink extends CWE22_P12_V1_ZephyrGlintSafeBase {
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
                    Logger.getLogger("CWE22_P12_V1_ZephyrGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_ZephyrGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

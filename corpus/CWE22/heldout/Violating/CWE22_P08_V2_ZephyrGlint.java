import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_ZephyrGlint {
    private static boolean privateTrue = true;

    public void openZephyrGlint() {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_GLINT_PATH");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_ZephyrGlintSink()).readZephyrGlint(dataArray);
    }
}

class CWE22_P08_V2_ZephyrGlintSink {
    public void readZephyrGlint(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_ZephyrGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_ZephyrGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

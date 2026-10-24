import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_SaffronGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSaffronGlint() {
        String data;
        if (IO.staticFive == 5) {
            data = (new CWE22_P07_V2_SaffronGlintSource()).locateSaffronGlint();
        } else {
            data = null;
        }
        String saffronGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronGlintFile = new File(saffronGlintRoot + data);
            FileInputStream saffronGlintStream = null;
            InputStreamReader saffronGlintStreamReader = null;
            BufferedReader saffronGlintReader = null;
            if (saffronGlintFile.exists() && saffronGlintFile.isFile()) {
                try {
                    saffronGlintStream = new FileInputStream(saffronGlintFile);
                    saffronGlintStreamReader = new InputStreamReader(saffronGlintStream, "UTF-8");
                    saffronGlintReader = new BufferedReader(saffronGlintStreamReader);
                    System.out.println(saffronGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_SaffronGlint").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronGlintReader != null) {
                            saffronGlintReader.close();
                        }
                        if (saffronGlintStreamReader != null) {
                            saffronGlintStreamReader.close();
                        }
                        if (saffronGlintStream != null) {
                            saffronGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_SaffronGlint").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_SaffronGlintSource {
    public String locateSaffronGlint() {
        String data;
        data = System.getenv("SAFFRON_GLINT_PATH");
        return data;
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openCrimsonLantern() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonLanternSafeBase baseObject = new CWE22_P12_V2_CrimsonLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonLanternSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonLanternSafeSink extends CWE22_P12_V2_CrimsonLanternSafeBase {
    public void action(String data) {
        String crimsonLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonLanternFile = new File(crimsonLanternRoot + data);
            FileInputStream crimsonLanternStream = null;
            InputStreamReader crimsonLanternStreamReader = null;
            BufferedReader crimsonLanternReader = null;
            if (crimsonLanternFile.exists() && crimsonLanternFile.isFile()) {
                try {
                    crimsonLanternStream = new FileInputStream(crimsonLanternFile);
                    crimsonLanternStreamReader = new InputStreamReader(crimsonLanternStream, "UTF-8");
                    crimsonLanternReader = new BufferedReader(crimsonLanternStreamReader);
                    System.out.println(crimsonLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonLanternReader != null) {
                            crimsonLanternReader.close();
                        }
                        if (crimsonLanternStreamReader != null) {
                            crimsonLanternStreamReader.close();
                        }
                        if (crimsonLanternStream != null) {
                            crimsonLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

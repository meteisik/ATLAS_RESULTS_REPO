import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openCrimsonHarbor() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("CRIMSON_HARBOR_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonHarborBase baseObject = new CWE22_P12_V2_CrimsonHarborSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonHarborBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonHarborSink extends CWE22_P12_V2_CrimsonHarborBase {
    public void action(String data) {
        String crimsonHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonHarborFile = new File(crimsonHarborRoot + data);
            FileInputStream crimsonHarborStream = null;
            InputStreamReader crimsonHarborStreamReader = null;
            BufferedReader crimsonHarborReader = null;
            if (crimsonHarborFile.exists() && crimsonHarborFile.isFile()) {
                try {
                    crimsonHarborStream = new FileInputStream(crimsonHarborFile);
                    crimsonHarborStreamReader = new InputStreamReader(crimsonHarborStream, "UTF-8");
                    crimsonHarborReader = new BufferedReader(crimsonHarborStreamReader);
                    System.out.println(crimsonHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonHarborReader != null) {
                            crimsonHarborReader.close();
                        }
                        if (crimsonHarborStreamReader != null) {
                            crimsonHarborStreamReader.close();
                        }
                        if (crimsonHarborStream != null) {
                            crimsonHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openCrimsonHelix() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("CRIMSON_HELIX_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonHelixBase baseObject = new CWE22_P12_V2_CrimsonHelixSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonHelixBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonHelixSink extends CWE22_P12_V2_CrimsonHelixBase {
    public void action(String data) {
        String crimsonHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonHelixFile = new File(crimsonHelixRoot + data);
            FileInputStream crimsonHelixStream = null;
            InputStreamReader crimsonHelixStreamReader = null;
            BufferedReader crimsonHelixReader = null;
            if (crimsonHelixFile.exists() && crimsonHelixFile.isFile()) {
                try {
                    crimsonHelixStream = new FileInputStream(crimsonHelixFile);
                    crimsonHelixStreamReader = new InputStreamReader(crimsonHelixStream, "UTF-8");
                    crimsonHelixReader = new BufferedReader(crimsonHelixStreamReader);
                    System.out.println(crimsonHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonHelixSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonHelixReader != null) {
                            crimsonHelixReader.close();
                        }
                        if (crimsonHelixStreamReader != null) {
                            crimsonHelixStreamReader.close();
                        }
                        if (crimsonHelixStream != null) {
                            crimsonHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonHelixSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

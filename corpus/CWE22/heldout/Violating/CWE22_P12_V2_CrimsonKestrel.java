import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openCrimsonKestrel() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_KESTREL_PATH");
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonKestrelBase baseObject = new CWE22_P12_V2_CrimsonKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonKestrelBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonKestrelSink extends CWE22_P12_V2_CrimsonKestrelBase {
    public void action(String data) {
        String crimsonKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonKestrelFile = new File(crimsonKestrelRoot + data);
            FileInputStream crimsonKestrelStream = null;
            InputStreamReader crimsonKestrelStreamReader = null;
            BufferedReader crimsonKestrelReader = null;
            if (crimsonKestrelFile.exists() && crimsonKestrelFile.isFile()) {
                try {
                    crimsonKestrelStream = new FileInputStream(crimsonKestrelFile);
                    crimsonKestrelStreamReader = new InputStreamReader(crimsonKestrelStream, "UTF-8");
                    crimsonKestrelReader = new BufferedReader(crimsonKestrelStreamReader);
                    System.out.println(crimsonKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonKestrelReader != null) {
                            crimsonKestrelReader.close();
                        }
                        if (crimsonKestrelStreamReader != null) {
                            crimsonKestrelStreamReader.close();
                        }
                        if (crimsonKestrelStream != null) {
                            crimsonKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

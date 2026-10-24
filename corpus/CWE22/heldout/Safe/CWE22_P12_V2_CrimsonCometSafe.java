import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V2_CrimsonCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openCrimsonComet() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE22_P12_V2_CrimsonCometSafeBase baseObject = new CWE22_P12_V2_CrimsonCometSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V2_CrimsonCometSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V2_CrimsonCometSafeSink extends CWE22_P12_V2_CrimsonCometSafeBase {
    public void action(String data) {
        String crimsonCometRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonCometFile = new File(crimsonCometRoot + data);
            FileInputStream crimsonCometStream = null;
            InputStreamReader crimsonCometStreamReader = null;
            BufferedReader crimsonCometReader = null;
            if (crimsonCometFile.exists() && crimsonCometFile.isFile()) {
                try {
                    crimsonCometStream = new FileInputStream(crimsonCometFile);
                    crimsonCometStreamReader = new InputStreamReader(crimsonCometStream, "UTF-8");
                    crimsonCometReader = new BufferedReader(crimsonCometStreamReader);
                    System.out.println(crimsonCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V2_CrimsonCometSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonCometReader != null) {
                            crimsonCometReader.close();
                        }
                        if (crimsonCometStreamReader != null) {
                            crimsonCometStreamReader.close();
                        }
                        if (crimsonCometStream != null) {
                            crimsonCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V2_CrimsonCometSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

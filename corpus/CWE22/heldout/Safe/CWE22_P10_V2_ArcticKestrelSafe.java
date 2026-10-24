import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ArcticKestrelSafe {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openArcticKestrel() {
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ArcticKestrelSafeSink()).readArcticKestrel();
    }
}

class CWE22_P10_V2_ArcticKestrelSafeSink {
    public void readArcticKestrel() {
        String data = CWE22_P10_V2_ArcticKestrelSafe.data;
        String arcticKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticKestrelFile = new File(arcticKestrelRoot + data);
            FileInputStream arcticKestrelStream = null;
            InputStreamReader arcticKestrelStreamReader = null;
            BufferedReader arcticKestrelReader = null;
            if (arcticKestrelFile.exists() && arcticKestrelFile.isFile()) {
                try {
                    arcticKestrelStream = new FileInputStream(arcticKestrelFile);
                    arcticKestrelStreamReader = new InputStreamReader(arcticKestrelStream, "UTF-8");
                    arcticKestrelReader = new BufferedReader(arcticKestrelStreamReader);
                    System.out.println(arcticKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ArcticKestrelSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticKestrelReader != null) {
                            arcticKestrelReader.close();
                        }
                        if (arcticKestrelStreamReader != null) {
                            arcticKestrelStreamReader.close();
                        }
                        if (arcticKestrelStream != null) {
                            arcticKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ArcticKestrelSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

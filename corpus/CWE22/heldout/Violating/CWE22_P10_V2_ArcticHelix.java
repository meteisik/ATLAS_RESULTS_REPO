import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_ArcticHelix {
    public static String data;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openArcticHelix() {
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_HELIX_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_ArcticHelixSink()).readArcticHelix();
    }
}

class CWE22_P10_V2_ArcticHelixSink {
    public void readArcticHelix() {
        String data = CWE22_P10_V2_ArcticHelix.data;
        String arcticHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticHelixFile = new File(arcticHelixRoot + data);
            FileInputStream arcticHelixStream = null;
            InputStreamReader arcticHelixStreamReader = null;
            BufferedReader arcticHelixReader = null;
            if (arcticHelixFile.exists() && arcticHelixFile.isFile()) {
                try {
                    arcticHelixStream = new FileInputStream(arcticHelixFile);
                    arcticHelixStreamReader = new InputStreamReader(arcticHelixStream, "UTF-8");
                    arcticHelixReader = new BufferedReader(arcticHelixStreamReader);
                    System.out.println(arcticHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_ArcticHelixSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticHelixReader != null) {
                            arcticHelixReader.close();
                        }
                        if (arcticHelixStreamReader != null) {
                            arcticHelixStreamReader.close();
                        }
                        if (arcticHelixStream != null) {
                            arcticHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_ArcticHelixSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

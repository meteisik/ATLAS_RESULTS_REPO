import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_JadeAuroraSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openJadeAurora() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String jadeAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeAuroraFile = new File(jadeAuroraRoot + data);
            FileInputStream jadeAuroraStream = null;
            InputStreamReader jadeAuroraStreamReader = null;
            BufferedReader jadeAuroraReader = null;
            if (jadeAuroraFile.exists() && jadeAuroraFile.isFile()) {
                try {
                    jadeAuroraStream = new FileInputStream(jadeAuroraFile);
                    jadeAuroraStreamReader = new InputStreamReader(jadeAuroraStream, "UTF-8");
                    jadeAuroraReader = new BufferedReader(jadeAuroraStreamReader);
                    System.out.println(jadeAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_JadeAuroraSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeAuroraReader != null) {
                            jadeAuroraReader.close();
                        }
                        if (jadeAuroraStreamReader != null) {
                            jadeAuroraStreamReader.close();
                        }
                        if (jadeAuroraStream != null) {
                            jadeAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_JadeAuroraSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

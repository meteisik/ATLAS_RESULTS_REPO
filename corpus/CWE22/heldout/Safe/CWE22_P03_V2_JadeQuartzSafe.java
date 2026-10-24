import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_JadeQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readJadeQuartz(String data) {
        String jadeQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeQuartzFile = new File(jadeQuartzRoot + data);
            FileInputStream jadeQuartzStream = null;
            InputStreamReader jadeQuartzStreamReader = null;
            BufferedReader jadeQuartzReader = null;
            if (jadeQuartzFile.exists() && jadeQuartzFile.isFile()) {
                try {
                    jadeQuartzStream = new FileInputStream(jadeQuartzFile);
                    jadeQuartzStreamReader = new InputStreamReader(jadeQuartzStream, "UTF-8");
                    jadeQuartzReader = new BufferedReader(jadeQuartzStreamReader);
                    System.out.println(jadeQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_JadeQuartzSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeQuartzReader != null) {
                            jadeQuartzReader.close();
                        }
                        if (jadeQuartzStreamReader != null) {
                            jadeQuartzStreamReader.close();
                        }
                        if (jadeQuartzStream != null) {
                            jadeQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_JadeQuartzSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openJadeQuartz() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        readJadeQuartz(data);
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SaffronPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSaffronPrism() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("SAFFRON_PRISM_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_SaffronPrismSink()).readSaffronPrism(data);
    }
}

class CWE22_P06_V2_SaffronPrismSink {
    public void readSaffronPrism(String data) {
        String saffronPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronPrismFile = new File(saffronPrismRoot + data);
            FileInputStream saffronPrismStream = null;
            InputStreamReader saffronPrismStreamReader = null;
            BufferedReader saffronPrismReader = null;
            if (saffronPrismFile.exists() && saffronPrismFile.isFile()) {
                try {
                    saffronPrismStream = new FileInputStream(saffronPrismFile);
                    saffronPrismStreamReader = new InputStreamReader(saffronPrismStream, "UTF-8");
                    saffronPrismReader = new BufferedReader(saffronPrismStreamReader);
                    System.out.println(saffronPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_SaffronPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronPrismReader != null) {
                            saffronPrismReader.close();
                        }
                        if (saffronPrismStreamReader != null) {
                            saffronPrismStreamReader.close();
                        }
                        if (saffronPrismStream != null) {
                            saffronPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_SaffronPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

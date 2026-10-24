import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_SaffronMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openSaffronMantis() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P06_V2_SaffronMantisSafeSink()).readSaffronMantis(data);
    }
}

class CWE22_P06_V2_SaffronMantisSafeSink {
    public void readSaffronMantis(String data) {
        String saffronMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronMantisFile = new File(saffronMantisRoot + data);
            FileInputStream saffronMantisStream = null;
            InputStreamReader saffronMantisStreamReader = null;
            BufferedReader saffronMantisReader = null;
            if (saffronMantisFile.exists() && saffronMantisFile.isFile()) {
                try {
                    saffronMantisStream = new FileInputStream(saffronMantisFile);
                    saffronMantisStreamReader = new InputStreamReader(saffronMantisStream, "UTF-8");
                    saffronMantisReader = new BufferedReader(saffronMantisStreamReader);
                    System.out.println(saffronMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_SaffronMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronMantisReader != null) {
                            saffronMantisReader.close();
                        }
                        if (saffronMantisStreamReader != null) {
                            saffronMantisStreamReader.close();
                        }
                        if (saffronMantisStream != null) {
                            saffronMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_SaffronMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

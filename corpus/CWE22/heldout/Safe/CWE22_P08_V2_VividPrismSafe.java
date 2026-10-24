import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_VividPrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openVividPrism() {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_VividPrismSafeSink()).readVividPrism(dataArray);
    }
}

class CWE22_P08_V2_VividPrismSafeSink {
    public void readVividPrism(String[] dataArray) {
        String data = dataArray[2];
        String vividPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File vividPrismFile = new File(vividPrismRoot + data);
            FileInputStream vividPrismStream = null;
            InputStreamReader vividPrismStreamReader = null;
            BufferedReader vividPrismReader = null;
            if (vividPrismFile.exists() && vividPrismFile.isFile()) {
                try {
                    vividPrismStream = new FileInputStream(vividPrismFile);
                    vividPrismStreamReader = new InputStreamReader(vividPrismStream, "UTF-8");
                    vividPrismReader = new BufferedReader(vividPrismStreamReader);
                    System.out.println(vividPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V2_VividPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividPrismReader != null) {
                            vividPrismReader.close();
                        }
                        if (vividPrismStreamReader != null) {
                            vividPrismStreamReader.close();
                        }
                        if (vividPrismStream != null) {
                            vividPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V2_VividPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

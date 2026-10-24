import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_AmberPrismSafe {
    public static String data;
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openAmberPrism() {
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_AmberPrismSafeSink()).readAmberPrism();
    }
}

class CWE22_P10_V2_AmberPrismSafeSink {
    public void readAmberPrism() {
        String data = CWE22_P10_V2_AmberPrismSafe.data;
        String amberPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File amberPrismFile = new File(amberPrismRoot + data);
            FileInputStream amberPrismStream = null;
            InputStreamReader amberPrismStreamReader = null;
            BufferedReader amberPrismReader = null;
            if (amberPrismFile.exists() && amberPrismFile.isFile()) {
                try {
                    amberPrismStream = new FileInputStream(amberPrismFile);
                    amberPrismStreamReader = new InputStreamReader(amberPrismStream, "UTF-8");
                    amberPrismReader = new BufferedReader(amberPrismStreamReader);
                    System.out.println(amberPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_AmberPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberPrismReader != null) {
                            amberPrismReader.close();
                        }
                        if (amberPrismStreamReader != null) {
                            amberPrismStreamReader.close();
                        }
                        if (amberPrismStream != null) {
                            amberPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_AmberPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

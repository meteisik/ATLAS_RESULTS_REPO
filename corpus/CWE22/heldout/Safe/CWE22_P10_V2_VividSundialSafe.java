import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_VividSundialSafe {
    public static String data;
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openVividSundial() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE22_P10_V2_VividSundialSafeSink()).readVividSundial();
    }
}

class CWE22_P10_V2_VividSundialSafeSink {
    public void readVividSundial() {
        String data = CWE22_P10_V2_VividSundialSafe.data;
        String vividSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File vividSundialFile = new File(vividSundialRoot + data);
            FileInputStream vividSundialStream = null;
            InputStreamReader vividSundialStreamReader = null;
            BufferedReader vividSundialReader = null;
            if (vividSundialFile.exists() && vividSundialFile.isFile()) {
                try {
                    vividSundialStream = new FileInputStream(vividSundialFile);
                    vividSundialStreamReader = new InputStreamReader(vividSundialStream, "UTF-8");
                    vividSundialReader = new BufferedReader(vividSundialStreamReader);
                    System.out.println(vividSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_VividSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividSundialReader != null) {
                            vividSundialReader.close();
                        }
                        if (vividSundialStreamReader != null) {
                            vividSundialStreamReader.close();
                        }
                        if (vividSundialStream != null) {
                            vividSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_VividSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

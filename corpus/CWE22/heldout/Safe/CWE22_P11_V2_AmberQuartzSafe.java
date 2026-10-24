import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAmberQuartz() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberQuartzSafeSink()).readAmberQuartz(dataHashMap);
    }
}

class CWE22_P11_V2_AmberQuartzSafeSink {
    public void readAmberQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String amberQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File amberQuartzFile = new File(amberQuartzRoot + data);
            FileInputStream amberQuartzStream = null;
            InputStreamReader amberQuartzStreamReader = null;
            BufferedReader amberQuartzReader = null;
            if (amberQuartzFile.exists() && amberQuartzFile.isFile()) {
                try {
                    amberQuartzStream = new FileInputStream(amberQuartzFile);
                    amberQuartzStreamReader = new InputStreamReader(amberQuartzStream, "UTF-8");
                    amberQuartzReader = new BufferedReader(amberQuartzStreamReader);
                    System.out.println(amberQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AmberQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberQuartzReader != null) {
                            amberQuartzReader.close();
                        }
                        if (amberQuartzStreamReader != null) {
                            amberQuartzStreamReader.close();
                        }
                        if (amberQuartzStream != null) {
                            amberQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AmberQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

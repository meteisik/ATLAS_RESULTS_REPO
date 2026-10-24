import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberSundialSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAmberSundial() {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberSundialSafeSink()).readAmberSundial(dataHashMap);
    }
}

class CWE22_P11_V2_AmberSundialSafeSink {
    public void readAmberSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String amberSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File amberSundialFile = new File(amberSundialRoot + data);
            FileInputStream amberSundialStream = null;
            InputStreamReader amberSundialStreamReader = null;
            BufferedReader amberSundialReader = null;
            if (amberSundialFile.exists() && amberSundialFile.isFile()) {
                try {
                    amberSundialStream = new FileInputStream(amberSundialFile);
                    amberSundialStreamReader = new InputStreamReader(amberSundialStream, "UTF-8");
                    amberSundialReader = new BufferedReader(amberSundialStreamReader);
                    System.out.println(amberSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AmberSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberSundialReader != null) {
                            amberSundialReader.close();
                        }
                        if (amberSundialStreamReader != null) {
                            amberSundialStreamReader.close();
                        }
                        if (amberSundialStream != null) {
                            amberSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AmberSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

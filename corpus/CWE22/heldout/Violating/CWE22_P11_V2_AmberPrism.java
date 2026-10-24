import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AmberPrism {
    private static boolean privateReturnsTrue() { return true; }

    public void openAmberPrism() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_PRISM_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AmberPrismSink()).readAmberPrism(dataHashMap);
    }
}

class CWE22_P11_V2_AmberPrismSink {
    public void readAmberPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V2_AmberPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V2_AmberPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

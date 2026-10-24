import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_AzurePrismSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openAzurePrism() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_AzurePrismSafeSink()).readAzurePrism(dataHashMap);
    }
}

class CWE22_P11_V2_AzurePrismSafeSink {
    public void readAzurePrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String azurePrismRoot = "/home/user/uploads/";
        if (data != null) {
            File azurePrismFile = new File(azurePrismRoot + data);
            FileInputStream azurePrismStream = null;
            InputStreamReader azurePrismStreamReader = null;
            BufferedReader azurePrismReader = null;
            if (azurePrismFile.exists() && azurePrismFile.isFile()) {
                try {
                    azurePrismStream = new FileInputStream(azurePrismFile);
                    azurePrismStreamReader = new InputStreamReader(azurePrismStream, "UTF-8");
                    azurePrismReader = new BufferedReader(azurePrismStreamReader);
                    System.out.println(azurePrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_AzurePrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (azurePrismReader != null) {
                            azurePrismReader.close();
                        }
                        if (azurePrismStreamReader != null) {
                            azurePrismStreamReader.close();
                        }
                        if (azurePrismStream != null) {
                            azurePrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_AzurePrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

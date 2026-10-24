import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openArcticHarbor() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("ARCTIC_HARBOR_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticHarborSink()).readArcticHarbor(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticHarborSink {
    public void readArcticHarbor(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticHarborFile = new File(arcticHarborRoot + data);
            FileInputStream arcticHarborStream = null;
            InputStreamReader arcticHarborStreamReader = null;
            BufferedReader arcticHarborReader = null;
            if (arcticHarborFile.exists() && arcticHarborFile.isFile()) {
                try {
                    arcticHarborStream = new FileInputStream(arcticHarborFile);
                    arcticHarborStreamReader = new InputStreamReader(arcticHarborStream, "UTF-8");
                    arcticHarborReader = new BufferedReader(arcticHarborStreamReader);
                    System.out.println(arcticHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticHarborReader != null) {
                            arcticHarborReader.close();
                        }
                        if (arcticHarborStreamReader != null) {
                            arcticHarborStreamReader.close();
                        }
                        if (arcticHarborStream != null) {
                            arcticHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

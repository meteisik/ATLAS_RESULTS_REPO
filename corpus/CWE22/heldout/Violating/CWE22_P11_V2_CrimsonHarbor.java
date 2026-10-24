import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CrimsonHarbor {
    private static boolean privateReturnsTrue() { return true; }

    public void openCrimsonHarbor() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_HARBOR_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CrimsonHarborSink()).readCrimsonHarbor(dataHashMap);
    }
}

class CWE22_P11_V2_CrimsonHarborSink {
    public void readCrimsonHarbor(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String crimsonHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonHarborFile = new File(crimsonHarborRoot + data);
            FileInputStream crimsonHarborStream = null;
            InputStreamReader crimsonHarborStreamReader = null;
            BufferedReader crimsonHarborReader = null;
            if (crimsonHarborFile.exists() && crimsonHarborFile.isFile()) {
                try {
                    crimsonHarborStream = new FileInputStream(crimsonHarborFile);
                    crimsonHarborStreamReader = new InputStreamReader(crimsonHarborStream, "UTF-8");
                    crimsonHarborReader = new BufferedReader(crimsonHarborStreamReader);
                    System.out.println(crimsonHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CrimsonHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonHarborReader != null) {
                            crimsonHarborReader.close();
                        }
                        if (crimsonHarborStreamReader != null) {
                            crimsonHarborStreamReader.close();
                        }
                        if (crimsonHarborStream != null) {
                            crimsonHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CrimsonHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

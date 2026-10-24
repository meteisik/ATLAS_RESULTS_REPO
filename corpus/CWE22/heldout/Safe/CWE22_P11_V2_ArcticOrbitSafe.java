import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticOrbitSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openArcticOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticOrbitSafeSink()).readArcticOrbit(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticOrbitSafeSink {
    public void readArcticOrbit(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticOrbitFile = new File(arcticOrbitRoot + data);
            FileInputStream arcticOrbitStream = null;
            InputStreamReader arcticOrbitStreamReader = null;
            BufferedReader arcticOrbitReader = null;
            if (arcticOrbitFile.exists() && arcticOrbitFile.isFile()) {
                try {
                    arcticOrbitStream = new FileInputStream(arcticOrbitFile);
                    arcticOrbitStreamReader = new InputStreamReader(arcticOrbitStream, "UTF-8");
                    arcticOrbitReader = new BufferedReader(arcticOrbitStreamReader);
                    System.out.println(arcticOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticOrbitSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticOrbitReader != null) {
                            arcticOrbitReader.close();
                        }
                        if (arcticOrbitStreamReader != null) {
                            arcticOrbitStreamReader.close();
                        }
                        if (arcticOrbitStream != null) {
                            arcticOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticOrbitSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

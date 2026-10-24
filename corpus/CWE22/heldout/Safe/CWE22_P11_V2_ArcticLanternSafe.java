import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticLanternSafe {

    public void openArcticLantern() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticLanternSafeSink()).readArcticLantern(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticLanternSafeSink {
    public void readArcticLantern(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticLanternFile = new File(arcticLanternRoot + data);
            FileInputStream arcticLanternStream = null;
            InputStreamReader arcticLanternStreamReader = null;
            BufferedReader arcticLanternReader = null;
            if (arcticLanternFile.exists() && arcticLanternFile.isFile()) {
                try {
                    arcticLanternStream = new FileInputStream(arcticLanternFile);
                    arcticLanternStreamReader = new InputStreamReader(arcticLanternStream, "UTF-8");
                    arcticLanternReader = new BufferedReader(arcticLanternStreamReader);
                    System.out.println(arcticLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticLanternReader != null) {
                            arcticLanternReader.close();
                        }
                        if (arcticLanternStreamReader != null) {
                            arcticLanternStreamReader.close();
                        }
                        if (arcticLanternStream != null) {
                            arcticLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

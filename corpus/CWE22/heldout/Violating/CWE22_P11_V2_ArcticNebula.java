import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticNebula {

    public void openArcticNebula() {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_NEBULA_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticNebulaSink()).readArcticNebula(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticNebulaSink {
    public void readArcticNebula(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticNebulaFile = new File(arcticNebulaRoot + data);
            FileInputStream arcticNebulaStream = null;
            InputStreamReader arcticNebulaStreamReader = null;
            BufferedReader arcticNebulaReader = null;
            if (arcticNebulaFile.exists() && arcticNebulaFile.isFile()) {
                try {
                    arcticNebulaStream = new FileInputStream(arcticNebulaFile);
                    arcticNebulaStreamReader = new InputStreamReader(arcticNebulaStream, "UTF-8");
                    arcticNebulaReader = new BufferedReader(arcticNebulaStreamReader);
                    System.out.println(arcticNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticNebulaSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticNebulaReader != null) {
                            arcticNebulaReader.close();
                        }
                        if (arcticNebulaStreamReader != null) {
                            arcticNebulaStreamReader.close();
                        }
                        if (arcticNebulaStream != null) {
                            arcticNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticNebulaSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

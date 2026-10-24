import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticRavenSafe {
    private static boolean privateTrue = true;

    public void openArcticRaven() {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticRavenSafeSink()).readArcticRaven(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticRavenSafeSink {
    public void readArcticRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticRavenFile = new File(arcticRavenRoot + data);
            FileInputStream arcticRavenStream = null;
            InputStreamReader arcticRavenStreamReader = null;
            BufferedReader arcticRavenReader = null;
            if (arcticRavenFile.exists() && arcticRavenFile.isFile()) {
                try {
                    arcticRavenStream = new FileInputStream(arcticRavenFile);
                    arcticRavenStreamReader = new InputStreamReader(arcticRavenStream, "UTF-8");
                    arcticRavenReader = new BufferedReader(arcticRavenStreamReader);
                    System.out.println(arcticRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticRavenReader != null) {
                            arcticRavenReader.close();
                        }
                        if (arcticRavenStreamReader != null) {
                            arcticRavenStreamReader.close();
                        }
                        if (arcticRavenStream != null) {
                            arcticRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

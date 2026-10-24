import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_CobaltRaven {
    private static boolean privateTrue = true;

    public void openCobaltRaven() {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_RAVEN_PATH");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_CobaltRavenSink()).readCobaltRaven(dataHashMap);
    }
}

class CWE22_P11_V2_CobaltRavenSink {
    public void readCobaltRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String cobaltRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltRavenFile = new File(cobaltRavenRoot + data);
            FileInputStream cobaltRavenStream = null;
            InputStreamReader cobaltRavenStreamReader = null;
            BufferedReader cobaltRavenReader = null;
            if (cobaltRavenFile.exists() && cobaltRavenFile.isFile()) {
                try {
                    cobaltRavenStream = new FileInputStream(cobaltRavenFile);
                    cobaltRavenStreamReader = new InputStreamReader(cobaltRavenStream, "UTF-8");
                    cobaltRavenReader = new BufferedReader(cobaltRavenStreamReader);
                    System.out.println(cobaltRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_CobaltRavenSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltRavenReader != null) {
                            cobaltRavenReader.close();
                        }
                        if (cobaltRavenStreamReader != null) {
                            cobaltRavenStreamReader.close();
                        }
                        if (cobaltRavenStream != null) {
                            cobaltRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_CobaltRavenSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

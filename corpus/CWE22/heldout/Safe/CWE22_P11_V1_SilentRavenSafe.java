import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentRavenSafe {

    public void openSilentRaven() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentRavenSafeSink()).readSilentRaven(dataHashMap);
    }
}

class CWE22_P11_V1_SilentRavenSafeSink {
    public void readSilentRaven(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File silentRavenFile = new File(silentRavenRoot + data);
            FileInputStream silentRavenStream = null;
            InputStreamReader silentRavenStreamReader = null;
            BufferedReader silentRavenReader = null;
            if (silentRavenFile.exists() && silentRavenFile.isFile()) {
                try {
                    silentRavenStream = new FileInputStream(silentRavenFile);
                    silentRavenStreamReader = new InputStreamReader(silentRavenStream, "UTF-8");
                    silentRavenReader = new BufferedReader(silentRavenStreamReader);
                    System.out.println(silentRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentRavenSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentRavenReader != null) {
                            silentRavenReader.close();
                        }
                        if (silentRavenStreamReader != null) {
                            silentRavenStreamReader.close();
                        }
                        if (silentRavenStream != null) {
                            silentRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentRavenSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

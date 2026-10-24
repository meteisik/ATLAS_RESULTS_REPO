import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_SilentHarborSafe {

    public void openSilentHarbor() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_SilentHarborSafeSink()).readSilentHarbor(dataHashMap);
    }
}

class CWE22_P11_V1_SilentHarborSafeSink {
    public void readSilentHarbor(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String silentHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File silentHarborFile = new File(silentHarborRoot + data);
            FileInputStream silentHarborStream = null;
            InputStreamReader silentHarborStreamReader = null;
            BufferedReader silentHarborReader = null;
            if (silentHarborFile.exists() && silentHarborFile.isFile()) {
                try {
                    silentHarborStream = new FileInputStream(silentHarborFile);
                    silentHarborStreamReader = new InputStreamReader(silentHarborStream, "UTF-8");
                    silentHarborReader = new BufferedReader(silentHarborStreamReader);
                    System.out.println(silentHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_SilentHarborSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (silentHarborReader != null) {
                            silentHarborReader.close();
                        }
                        if (silentHarborStreamReader != null) {
                            silentHarborStreamReader.close();
                        }
                        if (silentHarborStream != null) {
                            silentHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_SilentHarborSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

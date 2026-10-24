import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticKestrel {

    public void openArcticKestrel() {
        String data;
        while (true) {
            data = System.getenv("ARCTIC_KESTREL_PATH");
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticKestrelSink()).readArcticKestrel(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticKestrelSink {
    public void readArcticKestrel(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticKestrelFile = new File(arcticKestrelRoot + data);
            FileInputStream arcticKestrelStream = null;
            InputStreamReader arcticKestrelStreamReader = null;
            BufferedReader arcticKestrelReader = null;
            if (arcticKestrelFile.exists() && arcticKestrelFile.isFile()) {
                try {
                    arcticKestrelStream = new FileInputStream(arcticKestrelFile);
                    arcticKestrelStreamReader = new InputStreamReader(arcticKestrelStream, "UTF-8");
                    arcticKestrelReader = new BufferedReader(arcticKestrelStreamReader);
                    System.out.println(arcticKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticKestrelSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticKestrelReader != null) {
                            arcticKestrelReader.close();
                        }
                        if (arcticKestrelStreamReader != null) {
                            arcticKestrelStreamReader.close();
                        }
                        if (arcticKestrelStream != null) {
                            arcticKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticKestrelSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

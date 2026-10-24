import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V2_ArcticHelixSafe {

    public void openArcticHelix() {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V2_ArcticHelixSafeSink()).readArcticHelix(dataHashMap);
    }
}

class CWE22_P11_V2_ArcticHelixSafeSink {
    public void readArcticHelix(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String arcticHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticHelixFile = new File(arcticHelixRoot + data);
            FileInputStream arcticHelixStream = null;
            InputStreamReader arcticHelixStreamReader = null;
            BufferedReader arcticHelixReader = null;
            if (arcticHelixFile.exists() && arcticHelixFile.isFile()) {
                try {
                    arcticHelixStream = new FileInputStream(arcticHelixFile);
                    arcticHelixStreamReader = new InputStreamReader(arcticHelixStream, "UTF-8");
                    arcticHelixReader = new BufferedReader(arcticHelixStreamReader);
                    System.out.println(arcticHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V2_ArcticHelixSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticHelixReader != null) {
                            arcticHelixReader.close();
                        }
                        if (arcticHelixStreamReader != null) {
                            arcticHelixStreamReader.close();
                        }
                        if (arcticHelixStream != null) {
                            arcticHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V2_ArcticHelixSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V2_OnyxHarbor {
    private static boolean privateTrue = true;

    public void openOnyxHarbor() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_HARBOR_PATH");
        } else {
            data = null;
        }
        (new CWE22_P06_V2_OnyxHarborSink()).readOnyxHarbor(data);
    }
}

class CWE22_P06_V2_OnyxHarborSink {
    public void readOnyxHarbor(String data) {
        String onyxHarborRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxHarborFile = new File(onyxHarborRoot + data);
            FileInputStream onyxHarborStream = null;
            InputStreamReader onyxHarborStreamReader = null;
            BufferedReader onyxHarborReader = null;
            if (onyxHarborFile.exists() && onyxHarborFile.isFile()) {
                try {
                    onyxHarborStream = new FileInputStream(onyxHarborFile);
                    onyxHarborStreamReader = new InputStreamReader(onyxHarborStream, "UTF-8");
                    onyxHarborReader = new BufferedReader(onyxHarborStreamReader);
                    System.out.println(onyxHarborReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V2_OnyxHarborSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxHarborReader != null) {
                            onyxHarborReader.close();
                        }
                        if (onyxHarborStreamReader != null) {
                            onyxHarborStreamReader.close();
                        }
                        if (onyxHarborStream != null) {
                            onyxHarborStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V2_OnyxHarborSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

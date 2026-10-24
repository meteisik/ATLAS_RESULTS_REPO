import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_OnyxHarborSafe {

    public void openOnyxHarbor() {
        String data;
        data = (new CWE22_P07_V1_OnyxHarborSafeSource()).locateOnyxHarbor();
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
                    Logger.getLogger("CWE22_P07_V1_OnyxHarborSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P07_V1_OnyxHarborSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_OnyxHarborSafeSource {
    public String locateOnyxHarbor() {
        String data;
        data = "foo";
        return data;
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V1_OnyxNebula {

    public void openOnyxNebula() {
        String data;
        data = System.getenv("ONYX_NEBULA_PATH");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V1_OnyxNebulaSink()).readOnyxNebula(dataArray);
    }
}

class CWE22_P08_V1_OnyxNebulaSink {
    public void readOnyxNebula(String[] dataArray) {
        String data = dataArray[2];
        String onyxNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxNebulaFile = new File(onyxNebulaRoot + data);
            FileInputStream onyxNebulaStream = null;
            InputStreamReader onyxNebulaStreamReader = null;
            BufferedReader onyxNebulaReader = null;
            if (onyxNebulaFile.exists() && onyxNebulaFile.isFile()) {
                try {
                    onyxNebulaStream = new FileInputStream(onyxNebulaFile);
                    onyxNebulaStreamReader = new InputStreamReader(onyxNebulaStream, "UTF-8");
                    onyxNebulaReader = new BufferedReader(onyxNebulaStreamReader);
                    System.out.println(onyxNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P08_V1_OnyxNebulaSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxNebulaReader != null) {
                            onyxNebulaReader.close();
                        }
                        if (onyxNebulaStreamReader != null) {
                            onyxNebulaStreamReader.close();
                        }
                        if (onyxNebulaStream != null) {
                            onyxNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P08_V1_OnyxNebulaSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

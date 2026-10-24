import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_OnyxLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void openOnyxLantern() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_OnyxLanternSafeSink()).readOnyxLantern(dataContainer);
    }
}

class CWE22_P09_V1_OnyxLanternSafeSink {
    public void readOnyxLantern(CWE22_P09_V1_OnyxLanternSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String onyxLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxLanternFile = new File(onyxLanternRoot + data);
            FileInputStream onyxLanternStream = null;
            InputStreamReader onyxLanternStreamReader = null;
            BufferedReader onyxLanternReader = null;
            if (onyxLanternFile.exists() && onyxLanternFile.isFile()) {
                try {
                    onyxLanternStream = new FileInputStream(onyxLanternFile);
                    onyxLanternStreamReader = new InputStreamReader(onyxLanternStream, "UTF-8");
                    onyxLanternReader = new BufferedReader(onyxLanternStreamReader);
                    System.out.println(onyxLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_OnyxLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxLanternReader != null) {
                            onyxLanternReader.close();
                        }
                        if (onyxLanternStreamReader != null) {
                            onyxLanternStreamReader.close();
                        }
                        if (onyxLanternStream != null) {
                            onyxLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_OnyxLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

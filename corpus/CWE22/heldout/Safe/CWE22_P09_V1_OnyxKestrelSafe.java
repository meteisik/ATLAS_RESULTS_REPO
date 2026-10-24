import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_OnyxKestrelSafe {

    static class Container {
        public String containerOne;
    }

    public void openOnyxKestrel() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_OnyxKestrelSafeSink()).readOnyxKestrel(dataContainer);
    }
}

class CWE22_P09_V1_OnyxKestrelSafeSink {
    public void readOnyxKestrel(CWE22_P09_V1_OnyxKestrelSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String onyxKestrelRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxKestrelFile = new File(onyxKestrelRoot + data);
            FileInputStream onyxKestrelStream = null;
            InputStreamReader onyxKestrelStreamReader = null;
            BufferedReader onyxKestrelReader = null;
            if (onyxKestrelFile.exists() && onyxKestrelFile.isFile()) {
                try {
                    onyxKestrelStream = new FileInputStream(onyxKestrelFile);
                    onyxKestrelStreamReader = new InputStreamReader(onyxKestrelStream, "UTF-8");
                    onyxKestrelReader = new BufferedReader(onyxKestrelStreamReader);
                    System.out.println(onyxKestrelReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_OnyxKestrelSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxKestrelReader != null) {
                            onyxKestrelReader.close();
                        }
                        if (onyxKestrelStreamReader != null) {
                            onyxKestrelStreamReader.close();
                        }
                        if (onyxKestrelStream != null) {
                            onyxKestrelStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_OnyxKestrelSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V1_RuneLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void openRuneLantern() {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V1_RuneLanternSafeSink()).readRuneLantern(dataContainer);
    }
}

class CWE22_P09_V1_RuneLanternSafeSink {
    public void readRuneLantern(CWE22_P09_V1_RuneLanternSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String runeLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File runeLanternFile = new File(runeLanternRoot + data);
            FileInputStream runeLanternStream = null;
            InputStreamReader runeLanternStreamReader = null;
            BufferedReader runeLanternReader = null;
            if (runeLanternFile.exists() && runeLanternFile.isFile()) {
                try {
                    runeLanternStream = new FileInputStream(runeLanternFile);
                    runeLanternStreamReader = new InputStreamReader(runeLanternStream, "UTF-8");
                    runeLanternReader = new BufferedReader(runeLanternStreamReader);
                    System.out.println(runeLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V1_RuneLanternSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (runeLanternReader != null) {
                            runeLanternReader.close();
                        }
                        if (runeLanternStreamReader != null) {
                            runeLanternStreamReader.close();
                        }
                        if (runeLanternStream != null) {
                            runeLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V1_RuneLanternSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

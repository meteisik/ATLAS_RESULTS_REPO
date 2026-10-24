import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VividGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void openVividGlint() {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VividGlintSafeSink()).readVividGlint(dataContainer);
    }
}

class CWE22_P09_V2_VividGlintSafeSink {
    public void readVividGlint(CWE22_P09_V2_VividGlintSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String vividGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File vividGlintFile = new File(vividGlintRoot + data);
            FileInputStream vividGlintStream = null;
            InputStreamReader vividGlintStreamReader = null;
            BufferedReader vividGlintReader = null;
            if (vividGlintFile.exists() && vividGlintFile.isFile()) {
                try {
                    vividGlintStream = new FileInputStream(vividGlintFile);
                    vividGlintStreamReader = new InputStreamReader(vividGlintStream, "UTF-8");
                    vividGlintReader = new BufferedReader(vividGlintStreamReader);
                    System.out.println(vividGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VividGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (vividGlintReader != null) {
                            vividGlintReader.close();
                        }
                        if (vividGlintStreamReader != null) {
                            vividGlintStreamReader.close();
                        }
                        if (vividGlintStream != null) {
                            vividGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VividGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

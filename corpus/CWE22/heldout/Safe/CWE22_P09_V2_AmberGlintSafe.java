import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void openAmberGlint() {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberGlintSafeSink()).readAmberGlint(dataContainer);
    }
}

class CWE22_P09_V2_AmberGlintSafeSink {
    public void readAmberGlint(CWE22_P09_V2_AmberGlintSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File amberGlintFile = new File(amberGlintRoot + data);
            FileInputStream amberGlintStream = null;
            InputStreamReader amberGlintStreamReader = null;
            BufferedReader amberGlintReader = null;
            if (amberGlintFile.exists() && amberGlintFile.isFile()) {
                try {
                    amberGlintStream = new FileInputStream(amberGlintFile);
                    amberGlintStreamReader = new InputStreamReader(amberGlintStream, "UTF-8");
                    amberGlintReader = new BufferedReader(amberGlintStreamReader);
                    System.out.println(amberGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberGlintSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberGlintReader != null) {
                            amberGlintReader.close();
                        }
                        if (amberGlintStreamReader != null) {
                            amberGlintStreamReader.close();
                        }
                        if (amberGlintStream != null) {
                            amberGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberGlintSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberPrism {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void openAmberPrism() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_PRISM_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberPrismSink()).readAmberPrism(dataContainer);
    }
}

class CWE22_P09_V2_AmberPrismSink {
    public void readAmberPrism(CWE22_P09_V2_AmberPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File amberPrismFile = new File(amberPrismRoot + data);
            FileInputStream amberPrismStream = null;
            InputStreamReader amberPrismStreamReader = null;
            BufferedReader amberPrismReader = null;
            if (amberPrismFile.exists() && amberPrismFile.isFile()) {
                try {
                    amberPrismStream = new FileInputStream(amberPrismFile);
                    amberPrismStreamReader = new InputStreamReader(amberPrismStream, "UTF-8");
                    amberPrismReader = new BufferedReader(amberPrismStreamReader);
                    System.out.println(amberPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberPrismReader != null) {
                            amberPrismReader.close();
                        }
                        if (amberPrismStreamReader != null) {
                            amberPrismStreamReader.close();
                        }
                        if (amberPrismStream != null) {
                            amberPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

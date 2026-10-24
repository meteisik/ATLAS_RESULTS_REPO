import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberSundialSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void openAmberSundial() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberSundialSafeSink()).readAmberSundial(dataContainer);
    }
}

class CWE22_P09_V2_AmberSundialSafeSink {
    public void readAmberSundial(CWE22_P09_V2_AmberSundialSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File amberSundialFile = new File(amberSundialRoot + data);
            FileInputStream amberSundialStream = null;
            InputStreamReader amberSundialStreamReader = null;
            BufferedReader amberSundialReader = null;
            if (amberSundialFile.exists() && amberSundialFile.isFile()) {
                try {
                    amberSundialStream = new FileInputStream(amberSundialFile);
                    amberSundialStreamReader = new InputStreamReader(amberSundialStream, "UTF-8");
                    amberSundialReader = new BufferedReader(amberSundialStreamReader);
                    System.out.println(amberSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberSundialReader != null) {
                            amberSundialReader.close();
                        }
                        if (amberSundialStreamReader != null) {
                            amberSundialStreamReader.close();
                        }
                        if (amberSundialStream != null) {
                            amberSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

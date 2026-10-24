import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_AmberMantisSafe {

    static class Container {
        public String containerOne;
    }

    public void openAmberMantis() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_AmberMantisSafeSink()).readAmberMantis(dataContainer);
    }
}

class CWE22_P09_V2_AmberMantisSafeSink {
    public void readAmberMantis(CWE22_P09_V2_AmberMantisSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String amberMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File amberMantisFile = new File(amberMantisRoot + data);
            FileInputStream amberMantisStream = null;
            InputStreamReader amberMantisStreamReader = null;
            BufferedReader amberMantisReader = null;
            if (amberMantisFile.exists() && amberMantisFile.isFile()) {
                try {
                    amberMantisStream = new FileInputStream(amberMantisFile);
                    amberMantisStreamReader = new InputStreamReader(amberMantisStream, "UTF-8");
                    amberMantisReader = new BufferedReader(amberMantisStreamReader);
                    System.out.println(amberMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_AmberMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberMantisReader != null) {
                            amberMantisReader.close();
                        }
                        if (amberMantisStreamReader != null) {
                            amberMantisStreamReader.close();
                        }
                        if (amberMantisStream != null) {
                            amberMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_AmberMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetMantisSafe {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String containerOne;
    }

    public void openVelvetMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetMantisSafeSink()).readVelvetMantis(dataContainer);
    }
}

class CWE22_P09_V2_VelvetMantisSafeSink {
    public void readVelvetMantis(CWE22_P09_V2_VelvetMantisSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetMantisFile = new File(velvetMantisRoot + data);
            FileInputStream velvetMantisStream = null;
            InputStreamReader velvetMantisStreamReader = null;
            BufferedReader velvetMantisReader = null;
            if (velvetMantisFile.exists() && velvetMantisFile.isFile()) {
                try {
                    velvetMantisStream = new FileInputStream(velvetMantisFile);
                    velvetMantisStreamReader = new InputStreamReader(velvetMantisStream, "UTF-8");
                    velvetMantisReader = new BufferedReader(velvetMantisStreamReader);
                    System.out.println(velvetMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetMantisSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetMantisReader != null) {
                            velvetMantisReader.close();
                        }
                        if (velvetMantisStreamReader != null) {
                            velvetMantisStreamReader.close();
                        }
                        if (velvetMantisStream != null) {
                            velvetMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetMantisSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

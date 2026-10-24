import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetAuroraSafe {

    static class Container {
        public String containerOne;
    }

    public void openVelvetAurora() {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetAuroraSafeSink()).readVelvetAurora(dataContainer);
    }
}

class CWE22_P09_V2_VelvetAuroraSafeSink {
    public void readVelvetAurora(CWE22_P09_V2_VelvetAuroraSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetAuroraRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetAuroraFile = new File(velvetAuroraRoot + data);
            FileInputStream velvetAuroraStream = null;
            InputStreamReader velvetAuroraStreamReader = null;
            BufferedReader velvetAuroraReader = null;
            if (velvetAuroraFile.exists() && velvetAuroraFile.isFile()) {
                try {
                    velvetAuroraStream = new FileInputStream(velvetAuroraFile);
                    velvetAuroraStreamReader = new InputStreamReader(velvetAuroraStream, "UTF-8");
                    velvetAuroraReader = new BufferedReader(velvetAuroraStreamReader);
                    System.out.println(velvetAuroraReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetAuroraReader != null) {
                            velvetAuroraReader.close();
                        }
                        if (velvetAuroraStreamReader != null) {
                            velvetAuroraStreamReader.close();
                        }
                        if (velvetAuroraStream != null) {
                            velvetAuroraStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

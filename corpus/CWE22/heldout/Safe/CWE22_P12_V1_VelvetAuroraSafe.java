import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetAuroraSafe {

    public void openVelvetAurora() {
        String data;
        data = "foo";
        CWE22_P12_V1_VelvetAuroraSafeBase baseObject = new CWE22_P12_V1_VelvetAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetAuroraSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetAuroraSafeSink extends CWE22_P12_V1_VelvetAuroraSafeBase {
    public void action(String data) {
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
                    Logger.getLogger("CWE22_P12_V1_VelvetAuroraSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P12_V1_VelvetAuroraSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

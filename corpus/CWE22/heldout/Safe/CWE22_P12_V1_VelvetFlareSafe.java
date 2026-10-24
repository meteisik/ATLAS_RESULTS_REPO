import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetFlareSafe {

    public void openVelvetFlare() {
        String data;
        data = "foo";
        CWE22_P12_V1_VelvetFlareSafeBase baseObject = new CWE22_P12_V1_VelvetFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetFlareSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetFlareSafeSink extends CWE22_P12_V1_VelvetFlareSafeBase {
    public void action(String data) {
        String velvetFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetFlareFile = new File(velvetFlareRoot + data);
            FileInputStream velvetFlareStream = null;
            InputStreamReader velvetFlareStreamReader = null;
            BufferedReader velvetFlareReader = null;
            if (velvetFlareFile.exists() && velvetFlareFile.isFile()) {
                try {
                    velvetFlareStream = new FileInputStream(velvetFlareFile);
                    velvetFlareStreamReader = new InputStreamReader(velvetFlareStream, "UTF-8");
                    velvetFlareReader = new BufferedReader(velvetFlareStreamReader);
                    System.out.println(velvetFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VelvetFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetFlareReader != null) {
                            velvetFlareReader.close();
                        }
                        if (velvetFlareStreamReader != null) {
                            velvetFlareStreamReader.close();
                        }
                        if (velvetFlareStream != null) {
                            velvetFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VelvetFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

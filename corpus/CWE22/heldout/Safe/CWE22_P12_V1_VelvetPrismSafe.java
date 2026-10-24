import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetPrismSafe {

    public void openVelvetPrism() {
        String data;
        data = "foo";
        CWE22_P12_V1_VelvetPrismSafeBase baseObject = new CWE22_P12_V1_VelvetPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetPrismSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetPrismSafeSink extends CWE22_P12_V1_VelvetPrismSafeBase {
    public void action(String data) {
        String velvetPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetPrismFile = new File(velvetPrismRoot + data);
            FileInputStream velvetPrismStream = null;
            InputStreamReader velvetPrismStreamReader = null;
            BufferedReader velvetPrismReader = null;
            if (velvetPrismFile.exists() && velvetPrismFile.isFile()) {
                try {
                    velvetPrismStream = new FileInputStream(velvetPrismFile);
                    velvetPrismStreamReader = new InputStreamReader(velvetPrismStream, "UTF-8");
                    velvetPrismReader = new BufferedReader(velvetPrismStreamReader);
                    System.out.println(velvetPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VelvetPrismSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetPrismReader != null) {
                            velvetPrismReader.close();
                        }
                        if (velvetPrismStreamReader != null) {
                            velvetPrismStreamReader.close();
                        }
                        if (velvetPrismStream != null) {
                            velvetPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VelvetPrismSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

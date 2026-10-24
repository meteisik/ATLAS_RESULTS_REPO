import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P12_V1_VelvetCascadeSafe {

    public void openVelvetCascade() {
        String data;
        data = "foo";
        CWE22_P12_V1_VelvetCascadeSafeBase baseObject = new CWE22_P12_V1_VelvetCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE22_P12_V1_VelvetCascadeSafeBase {
    public abstract void action(String data);
}

class CWE22_P12_V1_VelvetCascadeSafeSink extends CWE22_P12_V1_VelvetCascadeSafeBase {
    public void action(String data) {
        String velvetCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetCascadeFile = new File(velvetCascadeRoot + data);
            FileInputStream velvetCascadeStream = null;
            InputStreamReader velvetCascadeStreamReader = null;
            BufferedReader velvetCascadeReader = null;
            if (velvetCascadeFile.exists() && velvetCascadeFile.isFile()) {
                try {
                    velvetCascadeStream = new FileInputStream(velvetCascadeFile);
                    velvetCascadeStreamReader = new InputStreamReader(velvetCascadeStream, "UTF-8");
                    velvetCascadeReader = new BufferedReader(velvetCascadeStreamReader);
                    System.out.println(velvetCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P12_V1_VelvetCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetCascadeReader != null) {
                            velvetCascadeReader.close();
                        }
                        if (velvetCascadeStreamReader != null) {
                            velvetCascadeStreamReader.close();
                        }
                        if (velvetCascadeStream != null) {
                            velvetCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P12_V1_VelvetCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

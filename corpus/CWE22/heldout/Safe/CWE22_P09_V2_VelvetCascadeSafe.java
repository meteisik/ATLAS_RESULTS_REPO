import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String containerOne;
    }

    public void openVelvetCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetCascadeSafeSink()).readVelvetCascade(dataContainer);
    }
}

class CWE22_P09_V2_VelvetCascadeSafeSink {
    public void readVelvetCascade(CWE22_P09_V2_VelvetCascadeSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V2_VelvetCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V2_VelvetCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

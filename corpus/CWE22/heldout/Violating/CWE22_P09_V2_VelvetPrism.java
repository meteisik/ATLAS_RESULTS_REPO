import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetPrism {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void openVelvetPrism() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_PRISM_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetPrismSink()).readVelvetPrism(dataContainer);
    }
}

class CWE22_P09_V2_VelvetPrismSink {
    public void readVelvetPrism(CWE22_P09_V2_VelvetPrism.Container dataContainer) {
        String data = dataContainer.containerOne;
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
                    Logger.getLogger("CWE22_P09_V2_VelvetPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P09_V2_VelvetPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

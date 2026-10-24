import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetQuartz {
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

    public void openVelvetQuartz() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("VELVET_QUARTZ_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetQuartzSink()).readVelvetQuartz(dataContainer);
    }
}

class CWE22_P09_V2_VelvetQuartzSink {
    public void readVelvetQuartz(CWE22_P09_V2_VelvetQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetQuartzRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetQuartzFile = new File(velvetQuartzRoot + data);
            FileInputStream velvetQuartzStream = null;
            InputStreamReader velvetQuartzStreamReader = null;
            BufferedReader velvetQuartzReader = null;
            if (velvetQuartzFile.exists() && velvetQuartzFile.isFile()) {
                try {
                    velvetQuartzStream = new FileInputStream(velvetQuartzFile);
                    velvetQuartzStreamReader = new InputStreamReader(velvetQuartzStream, "UTF-8");
                    velvetQuartzReader = new BufferedReader(velvetQuartzStreamReader);
                    System.out.println(velvetQuartzReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetQuartzSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetQuartzReader != null) {
                            velvetQuartzReader.close();
                        }
                        if (velvetQuartzStreamReader != null) {
                            velvetQuartzStreamReader.close();
                        }
                        if (velvetQuartzStream != null) {
                            velvetQuartzStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetQuartzSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

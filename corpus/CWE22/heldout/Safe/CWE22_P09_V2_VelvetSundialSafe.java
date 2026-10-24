import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetSundialSafe {
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

    public void openVelvetSundial() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetSundialSafeSink()).readVelvetSundial(dataContainer);
    }
}

class CWE22_P09_V2_VelvetSundialSafeSink {
    public void readVelvetSundial(CWE22_P09_V2_VelvetSundialSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetSundialFile = new File(velvetSundialRoot + data);
            FileInputStream velvetSundialStream = null;
            InputStreamReader velvetSundialStreamReader = null;
            BufferedReader velvetSundialReader = null;
            if (velvetSundialFile.exists() && velvetSundialFile.isFile()) {
                try {
                    velvetSundialStream = new FileInputStream(velvetSundialFile);
                    velvetSundialStreamReader = new InputStreamReader(velvetSundialStream, "UTF-8");
                    velvetSundialReader = new BufferedReader(velvetSundialStreamReader);
                    System.out.println(velvetSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetSundialReader != null) {
                            velvetSundialReader.close();
                        }
                        if (velvetSundialStreamReader != null) {
                            velvetSundialStreamReader.close();
                        }
                        if (velvetSundialStream != null) {
                            velvetSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

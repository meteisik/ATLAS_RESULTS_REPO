import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetSignal {
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

    public void openVelvetSignal() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("VELVET_SIGNAL_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetSignalSink()).readVelvetSignal(dataContainer);
    }
}

class CWE22_P09_V2_VelvetSignalSink {
    public void readVelvetSignal(CWE22_P09_V2_VelvetSignal.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetSignalFile = new File(velvetSignalRoot + data);
            FileInputStream velvetSignalStream = null;
            InputStreamReader velvetSignalStreamReader = null;
            BufferedReader velvetSignalReader = null;
            if (velvetSignalFile.exists() && velvetSignalFile.isFile()) {
                try {
                    velvetSignalStream = new FileInputStream(velvetSignalFile);
                    velvetSignalStreamReader = new InputStreamReader(velvetSignalStream, "UTF-8");
                    velvetSignalReader = new BufferedReader(velvetSignalStreamReader);
                    System.out.println(velvetSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetSignalReader != null) {
                            velvetSignalReader.close();
                        }
                        if (velvetSignalStreamReader != null) {
                            velvetSignalStreamReader.close();
                        }
                        if (velvetSignalStream != null) {
                            velvetSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

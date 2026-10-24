import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P08_V2_VelvetSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void openVelvetSignal() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE22_P08_V2_VelvetSignalSafeSink()).readVelvetSignal(dataArray);
    }
}

class CWE22_P08_V2_VelvetSignalSafeSink {
    public void readVelvetSignal(String[] dataArray) {
        String data = dataArray[2];
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
                    Logger.getLogger("CWE22_P08_V2_VelvetSignalSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P08_V2_VelvetSignalSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

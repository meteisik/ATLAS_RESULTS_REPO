import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V1_VelvetSignal {
    public static String data;

    public void openVelvetSignal() {
        data = System.getenv("VELVET_SIGNAL_PATH");
        (new CWE22_P10_V1_VelvetSignalSink()).readVelvetSignal();
    }
}

class CWE22_P10_V1_VelvetSignalSink {
    public void readVelvetSignal() {
        String data = CWE22_P10_V1_VelvetSignal.data;
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
                    Logger.getLogger("CWE22_P10_V1_VelvetSignalSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P10_V1_VelvetSignalSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

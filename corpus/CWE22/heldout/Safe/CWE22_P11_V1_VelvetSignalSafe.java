import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetSignalSafe {

    public void openVelvetSignal() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetSignalSafeSink()).readVelvetSignal(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetSignalSafeSink {
    public void readVelvetSignal(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_VelvetSignalSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_VelvetSignalSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

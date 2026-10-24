import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetSundialSafe {

    public void openVelvetSundial() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetSundialSafeSink()).readVelvetSundial(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetSundialSafeSink {
    public void readVelvetSundial(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_VelvetSundialSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_VelvetSundialSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

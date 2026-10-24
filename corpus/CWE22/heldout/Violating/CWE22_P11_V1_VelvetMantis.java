import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetMantis {

    public void openVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetMantisSink()).readVelvetMantis(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetMantisSink {
    public void readVelvetMantis(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String velvetMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetMantisFile = new File(velvetMantisRoot + data);
            FileInputStream velvetMantisStream = null;
            InputStreamReader velvetMantisStreamReader = null;
            BufferedReader velvetMantisReader = null;
            if (velvetMantisFile.exists() && velvetMantisFile.isFile()) {
                try {
                    velvetMantisStream = new FileInputStream(velvetMantisFile);
                    velvetMantisStreamReader = new InputStreamReader(velvetMantisStream, "UTF-8");
                    velvetMantisReader = new BufferedReader(velvetMantisStreamReader);
                    System.out.println(velvetMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VelvetMantisSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetMantisReader != null) {
                            velvetMantisReader.close();
                        }
                        if (velvetMantisStreamReader != null) {
                            velvetMantisStreamReader.close();
                        }
                        if (velvetMantisStream != null) {
                            velvetMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VelvetMantisSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

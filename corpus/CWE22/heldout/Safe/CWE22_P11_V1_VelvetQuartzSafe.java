import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetQuartzSafe {

    public void openVelvetQuartz() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetQuartzSafeSink()).readVelvetQuartz(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetQuartzSafeSink {
    public void readVelvetQuartz(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
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
                    Logger.getLogger("CWE22_P11_V1_VelvetQuartzSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P11_V1_VelvetQuartzSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

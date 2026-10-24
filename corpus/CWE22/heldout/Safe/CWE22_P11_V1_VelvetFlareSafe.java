import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetFlareSafe {

    public void openVelvetFlare() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetFlareSafeSink()).readVelvetFlare(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetFlareSafeSink {
    public void readVelvetFlare(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String velvetFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetFlareFile = new File(velvetFlareRoot + data);
            FileInputStream velvetFlareStream = null;
            InputStreamReader velvetFlareStreamReader = null;
            BufferedReader velvetFlareReader = null;
            if (velvetFlareFile.exists() && velvetFlareFile.isFile()) {
                try {
                    velvetFlareStream = new FileInputStream(velvetFlareFile);
                    velvetFlareStreamReader = new InputStreamReader(velvetFlareStream, "UTF-8");
                    velvetFlareReader = new BufferedReader(velvetFlareStreamReader);
                    System.out.println(velvetFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VelvetFlareSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetFlareReader != null) {
                            velvetFlareReader.close();
                        }
                        if (velvetFlareStreamReader != null) {
                            velvetFlareStreamReader.close();
                        }
                        if (velvetFlareStream != null) {
                            velvetFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VelvetFlareSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

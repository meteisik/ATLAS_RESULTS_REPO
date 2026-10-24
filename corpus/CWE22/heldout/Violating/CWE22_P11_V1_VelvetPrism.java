import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetPrism {

    public void openVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetPrismSink()).readVelvetPrism(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetPrismSink {
    public void readVelvetPrism(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String velvetPrismRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetPrismFile = new File(velvetPrismRoot + data);
            FileInputStream velvetPrismStream = null;
            InputStreamReader velvetPrismStreamReader = null;
            BufferedReader velvetPrismReader = null;
            if (velvetPrismFile.exists() && velvetPrismFile.isFile()) {
                try {
                    velvetPrismStream = new FileInputStream(velvetPrismFile);
                    velvetPrismStreamReader = new InputStreamReader(velvetPrismStream, "UTF-8");
                    velvetPrismReader = new BufferedReader(velvetPrismStreamReader);
                    System.out.println(velvetPrismReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VelvetPrismSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetPrismReader != null) {
                            velvetPrismReader.close();
                        }
                        if (velvetPrismStreamReader != null) {
                            velvetPrismStreamReader.close();
                        }
                        if (velvetPrismStream != null) {
                            velvetPrismStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VelvetPrismSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

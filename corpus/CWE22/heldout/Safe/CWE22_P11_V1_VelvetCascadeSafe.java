import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetCascadeSafe {

    public void openVelvetCascade() {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetCascadeSafeSink()).readVelvetCascade(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetCascadeSafeSink {
    public void readVelvetCascade(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String velvetCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetCascadeFile = new File(velvetCascadeRoot + data);
            FileInputStream velvetCascadeStream = null;
            InputStreamReader velvetCascadeStreamReader = null;
            BufferedReader velvetCascadeReader = null;
            if (velvetCascadeFile.exists() && velvetCascadeFile.isFile()) {
                try {
                    velvetCascadeStream = new FileInputStream(velvetCascadeFile);
                    velvetCascadeStreamReader = new InputStreamReader(velvetCascadeStream, "UTF-8");
                    velvetCascadeReader = new BufferedReader(velvetCascadeStreamReader);
                    System.out.println(velvetCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VelvetCascadeSafeSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetCascadeReader != null) {
                            velvetCascadeReader.close();
                        }
                        if (velvetCascadeStreamReader != null) {
                            velvetCascadeStreamReader.close();
                        }
                        if (velvetCascadeStream != null) {
                            velvetCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VelvetCascadeSafeSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

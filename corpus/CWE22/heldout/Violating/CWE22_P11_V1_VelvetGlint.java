import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P11_V1_VelvetGlint {

    public void openVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_PATH");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE22_P11_V1_VelvetGlintSink()).readVelvetGlint(dataHashMap);
    }
}

class CWE22_P11_V1_VelvetGlintSink {
    public void readVelvetGlint(HashMap<Integer, String> dataHashMap) {
        String data = dataHashMap.get(2);
        String velvetGlintRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetGlintFile = new File(velvetGlintRoot + data);
            FileInputStream velvetGlintStream = null;
            InputStreamReader velvetGlintStreamReader = null;
            BufferedReader velvetGlintReader = null;
            if (velvetGlintFile.exists() && velvetGlintFile.isFile()) {
                try {
                    velvetGlintStream = new FileInputStream(velvetGlintFile);
                    velvetGlintStreamReader = new InputStreamReader(velvetGlintStream, "UTF-8");
                    velvetGlintReader = new BufferedReader(velvetGlintStreamReader);
                    System.out.println(velvetGlintReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P11_V1_VelvetGlintSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetGlintReader != null) {
                            velvetGlintReader.close();
                        }
                        if (velvetGlintStreamReader != null) {
                            velvetGlintStreamReader.close();
                        }
                        if (velvetGlintStream != null) {
                            velvetGlintStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P11_V1_VelvetGlintSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_OnyxComet {

    public void openOnyxComet() {
        String data;
        data = (new CWE22_P07_V1_OnyxCometSource()).locateOnyxComet();
        String onyxCometRoot = "/home/user/uploads/";
        if (data != null) {
            File onyxCometFile = new File(onyxCometRoot + data);
            FileInputStream onyxCometStream = null;
            InputStreamReader onyxCometStreamReader = null;
            BufferedReader onyxCometReader = null;
            if (onyxCometFile.exists() && onyxCometFile.isFile()) {
                try {
                    onyxCometStream = new FileInputStream(onyxCometFile);
                    onyxCometStreamReader = new InputStreamReader(onyxCometStream, "UTF-8");
                    onyxCometReader = new BufferedReader(onyxCometStreamReader);
                    System.out.println(onyxCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_OnyxComet").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (onyxCometReader != null) {
                            onyxCometReader.close();
                        }
                        if (onyxCometStreamReader != null) {
                            onyxCometStreamReader.close();
                        }
                        if (onyxCometStream != null) {
                            onyxCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_OnyxComet").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_OnyxCometSource {
    public String locateOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_PATH");
        return data;
    }
}

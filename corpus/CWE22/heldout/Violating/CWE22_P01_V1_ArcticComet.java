import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_ArcticComet {

    public void openArcticComet() {
        String data;
        data = System.getenv("ARCTIC_COMET_PATH");
        String arcticCometRoot = "/home/user/uploads/";
        if (data != null) {
            File arcticCometFile = new File(arcticCometRoot + data);
            FileInputStream arcticCometStream = null;
            InputStreamReader arcticCometStreamReader = null;
            BufferedReader arcticCometReader = null;
            if (arcticCometFile.exists() && arcticCometFile.isFile()) {
                try {
                    arcticCometStream = new FileInputStream(arcticCometFile);
                    arcticCometStreamReader = new InputStreamReader(arcticCometStream, "UTF-8");
                    arcticCometReader = new BufferedReader(arcticCometStreamReader);
                    System.out.println(arcticCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_ArcticComet").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (arcticCometReader != null) {
                            arcticCometReader.close();
                        }
                        if (arcticCometStreamReader != null) {
                            arcticCometStreamReader.close();
                        }
                        if (arcticCometStream != null) {
                            arcticCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_ArcticComet").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

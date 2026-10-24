import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_ArcticLantern {

    public void openArcticLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LANTERN_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String arcticLanternRoot = "/home/user/uploads/";
            if (data != null) {
                File arcticLanternFile = new File(arcticLanternRoot + data);
                FileInputStream arcticLanternStream = null;
                InputStreamReader arcticLanternStreamReader = null;
                BufferedReader arcticLanternReader = null;
                if (arcticLanternFile.exists() && arcticLanternFile.isFile()) {
                    try {
                        arcticLanternStream = new FileInputStream(arcticLanternFile);
                        arcticLanternStreamReader = new InputStreamReader(arcticLanternStream, "UTF-8");
                        arcticLanternReader = new BufferedReader(arcticLanternStreamReader);
                        System.out.println(arcticLanternReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_ArcticLantern").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (arcticLanternReader != null) {
                                arcticLanternReader.close();
                            }
                            if (arcticLanternStreamReader != null) {
                                arcticLanternStreamReader.close();
                            }
                            if (arcticLanternStream != null) {
                                arcticLanternStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_ArcticLantern").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

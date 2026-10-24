import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_JadeQuartz {
    private static int privateFive = 5;

    public void openJadeQuartz() {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("JADE_QUARTZ_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String jadeQuartzRoot = "/home/user/uploads/";
            if (data != null) {
                File jadeQuartzFile = new File(jadeQuartzRoot + data);
                FileInputStream jadeQuartzStream = null;
                InputStreamReader jadeQuartzStreamReader = null;
                BufferedReader jadeQuartzReader = null;
                if (jadeQuartzFile.exists() && jadeQuartzFile.isFile()) {
                    try {
                        jadeQuartzStream = new FileInputStream(jadeQuartzFile);
                        jadeQuartzStreamReader = new InputStreamReader(jadeQuartzStream, "UTF-8");
                        jadeQuartzReader = new BufferedReader(jadeQuartzStreamReader);
                        System.out.println(jadeQuartzReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_JadeQuartz").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (jadeQuartzReader != null) {
                                jadeQuartzReader.close();
                            }
                            if (jadeQuartzStreamReader != null) {
                                jadeQuartzStreamReader.close();
                            }
                            if (jadeQuartzStream != null) {
                                jadeQuartzStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_JadeQuartz").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

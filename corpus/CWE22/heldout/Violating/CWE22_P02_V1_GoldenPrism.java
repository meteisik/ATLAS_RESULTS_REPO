import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_GoldenPrism {

    public void openGoldenPrism() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_PRISM_PATH");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String goldenPrismRoot = "/home/user/uploads/";
            if (data != null) {
                File goldenPrismFile = new File(goldenPrismRoot + data);
                FileInputStream goldenPrismStream = null;
                InputStreamReader goldenPrismStreamReader = null;
                BufferedReader goldenPrismReader = null;
                if (goldenPrismFile.exists() && goldenPrismFile.isFile()) {
                    try {
                        goldenPrismStream = new FileInputStream(goldenPrismFile);
                        goldenPrismStreamReader = new InputStreamReader(goldenPrismStream, "UTF-8");
                        goldenPrismReader = new BufferedReader(goldenPrismStreamReader);
                        System.out.println(goldenPrismReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V1_GoldenPrism").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (goldenPrismReader != null) {
                                goldenPrismReader.close();
                            }
                            if (goldenPrismStreamReader != null) {
                                goldenPrismStreamReader.close();
                            }
                            if (goldenPrismStream != null) {
                                goldenPrismStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V1_GoldenPrism").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

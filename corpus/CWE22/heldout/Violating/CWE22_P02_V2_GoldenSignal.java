import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_GoldenSignal {

    public void openGoldenSignal() {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("GOLDEN_SIGNAL_PATH");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String goldenSignalRoot = "/home/user/uploads/";
            if (data != null) {
                File goldenSignalFile = new File(goldenSignalRoot + data);
                FileInputStream goldenSignalStream = null;
                InputStreamReader goldenSignalStreamReader = null;
                BufferedReader goldenSignalReader = null;
                if (goldenSignalFile.exists() && goldenSignalFile.isFile()) {
                    try {
                        goldenSignalStream = new FileInputStream(goldenSignalFile);
                        goldenSignalStreamReader = new InputStreamReader(goldenSignalStream, "UTF-8");
                        goldenSignalReader = new BufferedReader(goldenSignalStreamReader);
                        System.out.println(goldenSignalReader.readLine());
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P02_V2_GoldenSignal").log(Level.WARNING, "Error with stream reading", exceptIO);
                    } finally {
                        try {
                            if (goldenSignalReader != null) {
                                goldenSignalReader.close();
                            }
                            if (goldenSignalStreamReader != null) {
                                goldenSignalStreamReader.close();
                            }
                            if (goldenSignalStream != null) {
                                goldenSignalStream.close();
                            }
                        } catch (IOException exceptIO) {
                            Logger.getLogger("CWE22_P02_V2_GoldenSignal").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}

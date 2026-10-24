import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_GoldenSignalSafe {

    public void openGoldenSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
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
                    Logger.getLogger("CWE22_P01_V2_GoldenSignalSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P01_V2_GoldenSignalSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

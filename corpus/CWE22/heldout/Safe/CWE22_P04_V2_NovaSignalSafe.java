import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_NovaSignalSafe {

    private String locateNovaSignal() {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openNovaSignal() {
        String data = locateNovaSignal();
        String novaSignalRoot = "/home/user/uploads/";
        if (data != null) {
            File novaSignalFile = new File(novaSignalRoot + data);
            FileInputStream novaSignalStream = null;
            InputStreamReader novaSignalStreamReader = null;
            BufferedReader novaSignalReader = null;
            if (novaSignalFile.exists() && novaSignalFile.isFile()) {
                try {
                    novaSignalStream = new FileInputStream(novaSignalFile);
                    novaSignalStreamReader = new InputStreamReader(novaSignalStream, "UTF-8");
                    novaSignalReader = new BufferedReader(novaSignalStreamReader);
                    System.out.println(novaSignalReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V2_NovaSignalSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaSignalReader != null) {
                            novaSignalReader.close();
                        }
                        if (novaSignalStreamReader != null) {
                            novaSignalStreamReader.close();
                        }
                        if (novaSignalStream != null) {
                            novaSignalStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V2_NovaSignalSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

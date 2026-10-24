import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P05_V1_GoldenSignal {
    private String goldenSignalData;

    private void readGoldenSignal() throws IOException {
        String data = goldenSignalData;
        String goldenSignalRoot = "/home/user/uploads/";
        File goldenSignalFile = new File(goldenSignalRoot + data);
        FileInputStream goldenSignalStream = new FileInputStream(goldenSignalFile);
        goldenSignalStream.close();
    }

    public void openGoldenSignal() throws IOException {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_PATH");
        goldenSignalData = data;
        readGoldenSignal();
    }
}

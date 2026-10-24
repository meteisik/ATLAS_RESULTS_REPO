import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetSignal {
    private static int privateFive = 5;

    public void runVelvetSignal() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = (new CWE89_P07_V2_VelvetSignalSource()).loadVelvetSignal();
        } else {
            data = null;
        }
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        Statement velvetSignalStatement = null;
        ResultSet velvetSignalRows = null;
        try {
            velvetSignalStatement = velvetSignalConnection.createStatement();
            velvetSignalRows = velvetSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSignalRows.getRow());
        } finally {
            if (velvetSignalRows != null) {
                velvetSignalRows.close();
            }
            if (velvetSignalStatement != null) {
                velvetSignalStatement.close();
            }
            velvetSignalConnection.close();
        }
    }
}

class CWE89_P07_V2_VelvetSignalSource {
    public String loadVelvetSignal() {
        String data;
        data = System.getenv("VELVET_SIGNAL_FILTER");
        return data;
    }
}

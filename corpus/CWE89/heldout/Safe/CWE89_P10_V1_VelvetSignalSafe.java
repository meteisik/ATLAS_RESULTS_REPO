import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetSignalSafe {

    public static String data;

    public void runVelvetSignal() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetSignalSafeSink()).queryVelvetSignal();
    }
}

class CWE89_P10_V1_VelvetSignalSafeSink {
    public void queryVelvetSignal() throws SQLException {
        String data = CWE89_P10_V1_VelvetSignalSafe.data;
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

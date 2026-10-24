import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetSundialSafe {

    public static String data;

    public void runVelvetSundial() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetSundialSafeSink()).queryVelvetSundial();
    }
}

class CWE89_P10_V1_VelvetSundialSafeSink {
    public void queryVelvetSundial() throws SQLException {
        String data = CWE89_P10_V1_VelvetSundialSafe.data;
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        Statement velvetSundialStatement = null;
        ResultSet velvetSundialRows = null;
        try {
            velvetSundialStatement = velvetSundialConnection.createStatement();
            velvetSundialRows = velvetSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSundialRows.getRow());
        } finally {
            if (velvetSundialRows != null) {
                velvetSundialRows.close();
            }
            if (velvetSundialStatement != null) {
                velvetSundialStatement.close();
            }
            velvetSundialConnection.close();
        }
    }
}

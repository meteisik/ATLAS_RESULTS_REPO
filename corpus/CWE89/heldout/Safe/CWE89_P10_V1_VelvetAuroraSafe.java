import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VelvetAuroraSafe {

    public static String data;

    public void runVelvetAurora() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_VelvetAuroraSafeSink()).queryVelvetAurora();
    }
}

class CWE89_P10_V1_VelvetAuroraSafeSink {
    public void queryVelvetAurora() throws SQLException {
        String data = CWE89_P10_V1_VelvetAuroraSafe.data;
        Connection velvetAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetAurora");
        Statement velvetAuroraStatement = null;
        ResultSet velvetAuroraRows = null;
        try {
            velvetAuroraStatement = velvetAuroraConnection.createStatement();
            velvetAuroraRows = velvetAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetAuroraRows.getRow());
        } finally {
            if (velvetAuroraRows != null) {
                velvetAuroraRows.close();
            }
            if (velvetAuroraStatement != null) {
                velvetAuroraStatement.close();
            }
            velvetAuroraConnection.close();
        }
    }
}

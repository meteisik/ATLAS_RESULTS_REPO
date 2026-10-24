import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VelvetAuroraSafe {

    public void runVelvetAurora() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VelvetAuroraSafeBase baseObject = new CWE89_P12_V1_VelvetAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VelvetAuroraSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VelvetAuroraSafeSink extends CWE89_P12_V1_VelvetAuroraSafeBase {
    public void action(String data) throws SQLException {
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

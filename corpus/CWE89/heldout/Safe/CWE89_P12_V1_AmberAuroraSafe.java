import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberAuroraSafe {

    public void runAmberAurora() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberAuroraSafeBase baseObject = new CWE89_P12_V1_AmberAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberAuroraSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberAuroraSafeSink extends CWE89_P12_V1_AmberAuroraSafeBase {
    public void action(String data) throws SQLException {
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        Statement amberAuroraStatement = null;
        ResultSet amberAuroraRows = null;
        try {
            amberAuroraStatement = amberAuroraConnection.createStatement();
            amberAuroraRows = amberAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberAuroraRows.getRow());
        } finally {
            if (amberAuroraRows != null) {
                amberAuroraRows.close();
            }
            if (amberAuroraStatement != null) {
                amberAuroraStatement.close();
            }
            amberAuroraConnection.close();
        }
    }
}

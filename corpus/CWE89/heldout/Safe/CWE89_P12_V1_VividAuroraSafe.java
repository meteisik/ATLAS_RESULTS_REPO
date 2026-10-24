import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividAuroraSafe {

    public void runVividAurora() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VividAuroraSafeBase baseObject = new CWE89_P12_V1_VividAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividAuroraSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividAuroraSafeSink extends CWE89_P12_V1_VividAuroraSafeBase {
    public void action(String data) throws SQLException {
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        Statement vividAuroraStatement = null;
        ResultSet vividAuroraRows = null;
        try {
            vividAuroraStatement = vividAuroraConnection.createStatement();
            vividAuroraRows = vividAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividAuroraRows.getRow());
        } finally {
            if (vividAuroraRows != null) {
                vividAuroraRows.close();
            }
            if (vividAuroraStatement != null) {
                vividAuroraStatement.close();
            }
            vividAuroraConnection.close();
        }
    }
}

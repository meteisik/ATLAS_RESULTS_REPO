import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividAurora {

    public void runVividAurora() throws SQLException {
        String data;
        data = System.getenv("VIVID_AURORA_FILTER");
        CWE89_P12_V1_VividAuroraBase baseObject = new CWE89_P12_V1_VividAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividAuroraBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividAuroraSink extends CWE89_P12_V1_VividAuroraBase {
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
